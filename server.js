// PayCST backend — MySQL + Express.
//
// What this replaces from the Flutter demo (item #15): the demo app keeps
// every username, password, PIN, and balance in a plain Dart Map that
// lives only in the app's RAM. Here, credentials are salted+hashed with
// bcrypt (never stored or compared as plaintext), every query is
// parameterized (no SQL injection surface), and login is enforced as two
// real steps — password, then a separately-verified PIN — before a usable
// session token is issued (items #1 / #11).
//
// This file intentionally covers the security-relevant slice (auth, PIN,
// wallet-to-wallet payment, groups with the 6-member cap, and admin
// oversight) rather than reimplementing every screen (bills/load/etc.) —
// those follow the exact same parameterized-query + hashed-auth pattern,
// so ask if you'd like them added too.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { mergeSort, comparators } = require('./mergeSort');
const { Stack } = require('./stack');
const { Queue } = require('./queue');

// ---------- pending-loan queue (FIFO — item: mandatory "Queue") ----------
const loanQueue = new Queue();

async function loadLoanQueueFromDatabase() {
  const [rows] = await pool.query(
    "SELECT id AS loanId, user_id AS userId FROM loans WHERE status = 'pending' ORDER BY created_at ASC"
  );
  loanQueue.items = []; // reset before rebuilding
  for (const row of rows) {
    loanQueue.enqueue(row);
  }
  console.log(`Loaded ${rows.length} pending loans into queue`);
}

const { DoublyLinkedList } = require('./dll');

// ---------- account doubly linked list (item: mandatory "Doubly Linked List") ----------
const accountList = new DoublyLinkedList();

async function loadAccountListFromDatabase() {
  const [rows] = await pool.query('SELECT * FROM users ORDER BY id ASC');
  accountList.clear();
  for (const row of rows) {
    accountList.insert(row.id, row);
  }
  console.log(`Loaded ${rows.length} accounts into doubly linked list`);
}

const { AVLTree } = require('./avl');

// ---------- wallet-ID AVL tree (item: mandatory "AVL Tree") ----------
const walletAvl = new AVLTree();

async function loadWalletAvlFromDatabase() {
  const [rows] = await pool.query('SELECT * FROM users');
  walletAvl.clear();
  for (const row of rows) {
    walletAvl.insert(row.wallet_id, row);
  }
  console.log(`Loaded ${rows.length} accounts into AVL tree (height: ${walletAvl.height()})`);
}

// ---------- per-user undo stacks (LIFO — item: mandatory "Stack") ----------
const undoStacks = new Map(); // userId -> Stack of transferRefs

function getUndoStack(userId) {
  if (!undoStacks.has(userId)) undoStacks.set(userId, new Stack());
  return undoStacks.get(userId);
}
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const http = require('http');
const { WebSocketServer } = require('ws');
const pool = require('./db');
const { PROVIDERS, findCheapestRoute } = require('./graph');
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection (server stayed up):', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception (server stayed up):', err);
});

const app = express();

// Railway (like most hosting platforms) puts the app behind a reverse
// proxy, so the real client IP arrives via the X-Forwarded-For header
// rather than the raw socket address. Without this, Express's req.ip
// (which express-rate-limit keys on) can't be trusted, and rate limiting
// silently fails to count attempts correctly per visitor.
app.set('trust proxy', 1);

// ---------- security middleware ----------
// helmet sets a batch of standard protective HTTP response headers
// (clickjacking protection, MIME-sniffing prevention, etc.) with sane
// defaults for an API-only server.
app.use(helmet());

// CORS is only relevant to browser clients (Flutter mobile doesn't send an
// Origin header, so this never affects the phone app either way). Set
// CORS_ORIGIN in .env to a comma-separated allowlist once you know your
// real web origin(s) (e.g. "https://app.paycst.com,https://paycst.com") to
// stop arbitrary sites from reading this API in a logged-in user's
// browser. Left unset, this keeps today's fully-open behavior so nothing
// breaks before you're ready to lock it down.
const corsOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim()).filter(Boolean)
  : null;
if (!corsOrigins) {
  console.warn('WARNING: CORS_ORIGIN is not set - any website origin is allowed. Set it in production.');
}
app.use(cors({ origin: corsOrigins || true }));
// Default express.json() limit is 100kb, which is too small for the
// base64-encoded ID front/back + selfie photos that /api/register sends —
// that route was almost certainly failing with a 413 before this. 15mb
// gives real photos room while still capping the body so a client can't
// send an unbounded payload as a cheap DoS.
// Large body (ID + selfie photos) only on registration; everything else 100kb.
app.use('/api/register', express.json({ limit: '15mb' }));
app.use(express.json({ limit: '100kb' }));

// Rate limiting on the endpoints most worth protecting against
// brute-force/credential-stuffing. A 4-digit PIN only has 10,000 possible
// values.
//
// Keyed by USERNAME rather than IP: Railway's multi-hop edge network can
// present a different X-Forwarded-For chain length per request, which
// makes req.ip unreliable even with `trust proxy` set — the same client
// can appear to come from a different "IP" on consecutive requests,
// silently defeating IP-based limiting. Username is a fixed, real value
// tied to the account under attack, so it can't be dodged by an attacker
// rotating source IPs — if anything this is the stronger defense for
// credential-stuffing specifically. Falls back to req.ip only when no
// username is present in the body (shouldn't normally happen on these
// routes, but keeps behavior sane rather than throwing).
function authKeyGenerator(req) {
  const username = req.body?.username?.toString().trim().toLowerCase();
  return username || ipKeyGenerator(req);
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per username per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authKeyGenerator,
  message: { error: 'Too many attempts. Please try again later.' },
});

// verify-pin doesn't carry a username in its body (it identifies the user
// via the pendingToken instead), so it needs its own keyGenerator that
// pulls the uid out of that token — otherwise every pending login in the
// last 5 minutes would fall back to the same req.ip bucket regardless of
// which account is actually being verified.
const pinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const payload = req.body?.pendingToken && verify(req.body.pendingToken);
    return payload?.uid ? `pin:${payload.uid}` : ipKeyGenerator(req);
  },
  message: { error: 'Too many attempts. Please try again later.' },
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authKeyGenerator,
  message: { error: 'Too many attempts. Please try again later.' },
});

// Second factor for admin login, mirroring pinLimiter above — keyed off
// the pendingToken's uid rather than username/IP for the same reason:
// this route doesn't carry a username in its body.
const adminPinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const payload = req.body?.pendingToken && verify(req.body.pendingToken);
    return payload?.uid ? `adminpin:${payload.uid}` : ipKeyGenerator(req);
  },
  message: { error: 'Too many attempts. Please try again later.' },
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET is missing or shorter than 32 characters.');
  process.exit(1);
}

// A precomputed bcrypt hash of a value nobody will ever type, used to keep
// login timing constant whether or not the username exists. Without this,
// a lookup miss returns instantly (skips bcrypt entirely) while a real
// username takes ~100ms for the hash compare, letting an attacker
// enumerate valid usernames purely from response time.
const DUMMY_BCRYPT_HASH = '$2b$10$mmbttYBoG2ai04iUGNVN1e//S9B9Ae8.xo6roaVcGlvA47DDiwhwO';
const MAX_GROUP_MEMBERS = 6;
const MAX_CENTAVOS = 100_000_000_00; // ₱100,000,000.00 — sanity ceiling, adjust as you like

// ---------- in-memory indexes (item #6 fix) ----------
// NOT the source of truth — MySQL is. These are fast lookup caches built
// from the database at startup and kept in sync after every commit that
// touches a user row. Safe to discard and rebuild at any time via
// loadIndexesFromDatabase().
const usersByUsername = new Map(); // username -> user row
const usersByWalletId = new Map(); // wallet_id -> user row 
async function loadIndexesFromDatabase() {
  const [rows] = await pool.query('SELECT * FROM users');
  usersByUsername.clear();
  usersByWalletId.clear();
  for (const row of rows) {
    usersByUsername.set(row.username, row);
    usersByWalletId.set(row.wallet_id, row);
  }
  console.log(`Loaded ${rows.length} users into hash map indexes`);
}

// ---------- live balance push (WebSocket) ----------
// userId -> Set of open sockets. A user can have more than one (two
// devices, a hot-reloaded app, etc), so every route just calls
// refreshUserInIndex(id) as it already did — this rides along on that
// same call rather than needing its own call site at every transfer.
const userSockets = new Map();

function registerSocket(userId, ws) {
  if (!userSockets.has(userId)) userSockets.set(userId, new Set());
  userSockets.get(userId).add(ws);
}

function unregisterSocket(userId, ws) {
  const set = userSockets.get(userId);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) userSockets.delete(userId);
}

function pushToUser(userId, payload) {
  const set = userSockets.get(userId);
  if (!set || set.size === 0) return;
  const msg = JSON.stringify(payload);
  for (const ws of set) {
    if (ws.readyState === ws.OPEN) ws.send(msg);
  }
}

async function refreshUserInIndex(userId) {
  const [[row]] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
  if (!row) {
    // User was deleted — grab the wallet_id from what we still have
    // cached (the DB row is already gone) so we can clean up the AVL
    // tree too, then remove from both structures.
    const oldNode = accountList.nodesByKey.get(userId);
    if (oldNode) {
      walletAvl.delete(oldNode.data.wallet_id);
      accountList.delete(userId);
    }
    return;
  }

  usersByUsername.set(row.username, row);
  usersByWalletId.set(row.wallet_id, row);

  if (accountList.nodesByKey.has(userId)) {
    accountList.update(userId, row);
  } else {
    accountList.insert(userId, row);
  }

  // item: mandatory "AVL Tree" — insert on first sight, update
  // thereafter (insert() handles both cases). Keyed by wallet_id, which
  // never changes once assigned, so this is safe to call every time.
  walletAvl.insert(row.wallet_id, row);

  // Push the fresh balance straight to any connected device for this
  // user — this is what makes an incoming transfer show up live instead
  // of waiting for the next poll/login. Every route that changes a
  // balance (send, wallet pay, group withdraw approval, loan payout,
  // admin reversal, undo, etc.) already calls refreshUserInIndex() for
  // every affected user right after commit, so hooking it here covers
  // all of them for free instead of needing a push call at each one.
  pushToUser(userId, { type: 'balance', balanceCentavos: toCentavos(row.balance) });
}

// ---------- money handling: integer centavos everywhere (item #1 fix) ----------
//
// Every peso amount that touches the database, an API request/response
// body, or in-process arithmetic is now a plain INTEGER count of centavos
// (₱1.00 == 100 centavos, so ₱150.50 == 15050). Previously amounts were
// JS `Number`s backed by MySQL `DECIMAL` columns — both are float-adjacent
// representations, and repeated add/subtract (payments, contributions,
// loan repayments) can silently drift a centavo here and there over time,
// or accept "amounts" like 10.005 that don't correspond to real money.
// Integers don't have that failure mode.
//
// CLIENT CONTRACT CHANGE: the Flutter app must send and expect every
// amount field as an integer number of centavos, not a decimal like
// 150.50 — send 15050 instead, and divide by 100 only when *displaying*
// a value to the user. See the migration note at the bottom of this file
// for the required DB column changes (DECIMAL -> INT).

// Validates an amount coming FROM a client request. Only accepts a
// strictly positive integer (fractional centavos aren't a real unit).
// Returns null (not a thrown error) on anything invalid so callers can
// respond with a normal 400.
function parseCentavos(value) {
  const n = typeof value === 'string' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isFinite(n)) return null;
  if (!Number.isInteger(n)) return null;
  if (n <= 0) return null;
  if (n > MAX_CENTAVOS) return null;
  return n;
}

// Normalizes a value coming FROM the database. mysql2 returns some large
// integer column types as strings rather than JS numbers, so every stored
// balance/amount is passed through this before arithmetic or comparisons.
function toCentavos(dbValue) {
  const n = typeof dbValue === 'string' ? parseInt(dbValue, 10) : dbValue;
  return Number.isSafeInteger(n) ? n : 0;
}

// Only for building human-readable error/display strings — never for
// storage or arithmetic.
function centavosToPesosLabel(centavos) {
  return (centavos / 100).toFixed(2);
}

// Pinned explicitly on both sign and verify so a token is only ever
// accepted under the one algorithm this server actually issues — jwt.verify
// otherwise accepts whatever algorithm family matches the secret's type,
// which is unnecessary attack surface to leave open even though a
// symmetric secret isn't vulnerable to the classic RS256->HS256 confusion
// attack.
const JWT_ALGORITHM = 'HS256';

function sign(payload, expiresIn) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn, algorithm: JWT_ALGORITHM });
}

function verify(token) {
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
  } catch {
    return null;
  }
}

// Wraps an async Express route handler so any rejected promise (a thrown
// error, a failed query, a missing table, etc.) is forwarded to
// Express's error-handling middleware via next(err) instead of being
// silently swallowed as an "unhandled rejection" — which previously left
// the client hanging forever with no response at all.
function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

// Requires a FULL session token (password + PIN both verified).
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const payload = token && verify(token);
    if (!payload || payload.stage !== 'full' || payload.role !== 'user') {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    // Suspension must take effect immediately, not only at the next login -
    // a 2h token issued before suspension would otherwise keep working.
    const [[row]] = await pool.query('SELECT status FROM users WHERE id = ?', [payload.uid]);
    if (!row) return res.status(401).json({ error: 'Not authenticated' });
    if (row.status === 'suspended') {
      return res.status(403).json({ error: 'This account has been suspended. Contact support for assistance.' });
    }
    req.userId = payload.uid;
    next();
  } catch (err) {
    next(err);
  }
}

// ---------- extra hardening helpers ----------
// Per-user cap on money actions, so one login can't hammer send/pay/load/bills
// (or guess which numbers are registered through "recipient not found").
const moneyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.userId ? `u:${req.userId}` : ipKeyGenerator(req)),
  message: { error: 'Too many payments in a short time. Please wait a minute and try again.' },
});

// Records what each admin did. Best effort: a logging problem never blocks the action.
async function logAdmin(req, action, targetType, targetId, details) {
  try {
    await pool.execute(
      'INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, details, ip) VALUES (?,?,?,?,?,?)',
      [req.adminId, action, targetType, String(targetId ?? ''), details ? JSON.stringify(details) : null, (req.ip || '').toString().slice(0, 64)]
    );
  } catch (err) {
    console.error('Audit log write failed:', err.message);
  }
}

// Admin sign-in attempts (successful and failed) go in the same log, so you
// can see if someone is guessing admin passwords or PINs.
async function logAdminEvent(req, action, adminId, who) {
  try {
    await pool.execute(
      'INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, details, ip) VALUES (?,?,?,?,?,?)',
      [adminId ?? null, action, 'admin_login', cleanText(who, 60), null, (req.ip || '').toString().slice(0, 64)]
    );
  } catch (err) {
    console.error('Audit log write failed:', err.message);
  }
}

// ID photos waiting for review are encrypted in the database (AES-256-GCM).
// Set PHOTO_ENCRYPTION_KEY to 64 hex characters:
//   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
// Without the key, photos are stored as before. Set it before the first sign-up.
const PHOTO_KEY = /^[0-9a-f]{64}$/i.test(process.env.PHOTO_ENCRYPTION_KEY || '')
  ? Buffer.from(process.env.PHOTO_ENCRYPTION_KEY, 'hex')
  : null;
if (!PHOTO_KEY) console.warn('WARNING: PHOTO_ENCRYPTION_KEY is not set - ID photos are stored unencrypted.');

function encryptPhoto(text) {
  if (!PHOTO_KEY || !text) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', PHOTO_KEY, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return 'enc:v1:' + Buffer.concat([iv, cipher.getAuthTag(), enc]).toString('base64');
}

function decryptPhoto(text) {
  if (typeof text !== 'string' || !text.startsWith('enc:v1:')) return text;
  if (!PHOTO_KEY) return '';
  try {
    const raw = Buffer.from(text.slice(7), 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', PHOTO_KEY, raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
  } catch {
    return '';
  }
}

// Free text that admins will read (group names, reasons, loan purpose...):
// trimmed, length-capped, and stripped of < > and control characters so it
// can't carry HTML/script into the admin panel.
function cleanText(value, max) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f<>]/g, '')
    .trim()
    .slice(0, max);
}

// Money actions (send, QR pay, load, bill pay) need the PIN again, so a stolen
// login token alone can't drain a wallet. Uses the same persistent lockout
// counter as the login PIN step, so guessing is throttled the same way.
async function verifyActionPin(userId, pin) {
  if (typeof pin !== 'string' || !/^\d{4}$/.test(pin)) {
    return { status: 400, error: 'Enter your 4-digit PIN to confirm' };
  }
  const identifier = `pin:${userId}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    return { status: 429, error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` };
  }
  const [[row]] = await pool.query('SELECT pin_hash FROM users WHERE id = ?', [userId]);
  const ok = await bcrypt.compare(pin, row ? row.pin_hash : DUMMY_BCRYPT_HASH);
  if (!ok) {
    await recordFailedAttempt(identifier);
    return { status: 401, error: 'Incorrect PIN' };
  }
  await clearAttempts(identifier);
  return null;
}

async function requirePin(req, res, next) {
  try {
    const failure = await verifyActionPin(req.userId, req.body?.pin);
    if (failure) return res.status(failure.status).json({ error: failure.error });
    next();
  } catch (err) {
    next(err);
  }
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verify(token);
  if (!payload || payload.role !== 'admin' || payload.stage !== 'full') {
    return res.status(401).json({ error: 'Not authenticated as admin' });
  }
  req.adminId = payload.uid;
  next();
}


// ---------- database-backed login lockout ----------
//
// Complements (doesn't replace) the in-memory express-rate-limit above.
// That limiter resets on every restart/redeploy — fine as a first line of
// defense, but not durable. This is the real enforcement: it persists in
// MySQL, so a restart can't reset an attacker's attempt count back to
// zero. Mirrors the "3 attempts then a cooldown" behavior the Flutter
// UI already implies client-side, except enforced here on the server so
// it can't be bypassed by calling the API directly (as our own curl
// testing demonstrated the client-side version could be).
// Escalating lockout tiers, strictest first. A flat "3 attempts, wait 30s"
// forever is cheap for an attacker to grind through indefinitely,
// especially against a 4-digit PIN (10,000 possibilities) — so repeated
// cycles of failures now escalate into much longer locks instead of
// resetting to the same 30s cost every time.
const LOCKOUT_TIERS = [
  { attempts: 10, lockoutSeconds: 30 * 60 }, // 10 failures in 30 min -> 30 min lock
  { attempts: 6, lockoutSeconds: 5 * 60 },   // 6 failures in 5 min -> 5 min lock
  { attempts: 3, lockoutSeconds: 30 },       // 3 failures in 30 sec -> 30 sec lock
];

// Returns null if not locked, or the number of seconds remaining if it is.
async function checkLockout(identifier) {
  for (const tier of LOCKOUT_TIERS) {
    const [[{ count }]] = await pool.query(
      'SELECT COUNT(*) AS count FROM login_attempts WHERE identifier = ? AND attempted_at > (NOW() - INTERVAL ? SECOND)',
      [identifier, tier.lockoutSeconds]
    );
    if (count < tier.attempts) continue;

    const [[oldest]] = await pool.query(
      'SELECT attempted_at FROM login_attempts WHERE identifier = ? ORDER BY attempted_at DESC LIMIT 1 OFFSET ?',
      [identifier, tier.attempts - 1]
    );
    const unlockAt = new Date(oldest.attempted_at).getTime() + tier.lockoutSeconds * 1000;
    const secondsLeft = Math.max(1, Math.ceil((unlockAt - Date.now()) / 1000));
    if (secondsLeft > 0) return secondsLeft;
  }
  return null;
}

async function recordFailedAttempt(identifier) {
  await pool.execute('INSERT INTO login_attempts (identifier) VALUES (?)', [identifier]);
}

async function clearAttempts(identifier) {
  await pool.execute('DELETE FROM login_attempts WHERE identifier = ?', [identifier]);
}

// ---------- Face++ face-matching (identity verification) ----------
//
// Compares two face photos (a government ID photo and a live selfie) and
// returns a similarity score from 0-100. This is a REAL third-party call —
// unlike the provider-routing simulation elsewhere in this file — but the
// score alone doesn't decide anything by itself; the caller decides the
// threshold for auto-approval vs. sending to manual admin review.

const FACEPP_API_KEY = process.env.FACEPP_API_KEY;
const FACEPP_API_SECRET = process.env.FACEPP_API_SECRET;
const FACEPP_COMPARE_URL = 'https://api-us.faceplusplus.com/facepp/v3/compare';

// image1Base64 / image2Base64 should be raw base64 (no "data:image/..." prefix).
// Returns { confidence, matched } on success, or throws on a Face++/network error.
// Free Face++ keys only allow about one request at a time. Registration makes
// several Face++ calls in a row (duplicate search, ID comparison, adding the
// face), so any of them can come back "CONCURRENCY_LIMIT_EXCEEDED". Instead of
// failing (which sent accounts to manual review with no score), wait a moment
// and try again, up to 4 times.
async function faceppFetch(url, form) {
  let last = null;
  for (const waitMs of [0, 1200, 2400, 3600]) {
    if (waitMs) await new Promise((resolve) => setTimeout(resolve, waitMs));
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    const data = await res.json();
    last = { res, data };
    if (!/CONCURRENCY_LIMIT_EXCEEDED/i.test(data.error_message || '')) break;
  }
  return last;
}

async function compareFaces(image1Base64, image2Base64) {
  if (!FACEPP_API_KEY || !FACEPP_API_SECRET) {
    throw new Error('Face verification is not configured on the server');
  }

  const form = new URLSearchParams();
  form.set('api_key', FACEPP_API_KEY);
  form.set('api_secret', FACEPP_API_SECRET);
  form.set('image_base64_1', image1Base64);
  form.set('image_base64_2', image2Base64);

  const { res, data } = await faceppFetch(FACEPP_COMPARE_URL, form);

  if (!res.ok || data.error_message) {
    throw new Error(data.error_message || 'Face comparison failed');
  }
  if (!data.faces1?.length || !data.faces2?.length) {
    throw new Error('Could not detect a face in one or both images');
  }

  // Face++'s own suggested threshold for a 1e-3 false-accept-rate is roughly
  // 62.3 — using 65 here as a slightly stricter, simple constant. Anything
  // under this goes to manual admin review rather than auto-rejecting, since
  // lighting/angle can legitimately lower a real match's score.
  const confidence = data.confidence ?? 0;
  return { confidence, matched: confidence >= 65 };
}

// ---------- Face++ duplicate-face check (one face = one account) ----------
//
// compareFaces() above only checks that the selfie matches the ID photo in the
// SAME submission. It can't tell if this face already has another account. For
// that, every registered selfie is stored in a Face++ FaceSet and each new
// selfie is searched against it. If any Face++ call fails the check is
// skipped (fail-open, same as compareFaces) so registration never breaks.
const FACEPP_BASE = 'https://api-us.faceplusplus.com/facepp/v3';
const FACESET_OUTER_ID = process.env.FACESET_OUTER_ID || 'paycst_users';
// Similarity (0-100) at or above which a new selfie counts as "already registered".
const FACE_DUPLICATE_THRESHOLD = Number(process.env.FACE_DUPLICATE_THRESHOLD || 80);
let faceSetReady = false;

async function faceppPost(path, fields) {
  const form = new URLSearchParams();
  form.set('api_key', FACEPP_API_KEY);
  form.set('api_secret', FACEPP_API_SECRET);
  for (const [k, v] of Object.entries(fields)) form.set(k, v);
  const { res, data } = await faceppFetch(`${FACEPP_BASE}${path}`, form);
  if (!res.ok || data.error_message) throw new Error(data.error_message || `Face++ ${path} failed`);
  return data;
}

async function ensureFaceSet() {
  if (faceSetReady) return;
  try {
    await faceppPost('/faceset/create', { outer_id: FACESET_OUTER_ID, display_name: 'PayCST users' });
  } catch (err) {
    if (!/FACESET_EXIST/i.test(err.message)) throw err;
  }
  faceSetReady = true;
}

async function detectFaceToken(imageBase64) {
  const data = await faceppPost('/detect', { image_base64: imageBase64 });
  if (!data.faces?.length) throw new Error('No face detected in selfie');
  return data.faces[0].face_token;
}

// Returns the best match ({ confidence, ... }) if this face is already in the
// FaceSet at/above the threshold, otherwise null.
async function findDuplicateFace(faceToken) {
  try {
    const data = await faceppPost('/search', { face_token: faceToken, outer_id: FACESET_OUTER_ID });
    const top = data.results?.[0];
    return top && top.confidence >= FACE_DUPLICATE_THRESHOLD ? top : null;
  } catch (err) {
    if (/EMPTY_FACESET|FACESET_NOT_FOUND/i.test(err.message)) return null; // nobody registered yet
    throw err;
  }
}

async function addFaceToIndex(faceToken) {
  await faceppPost('/faceset/addface', { outer_id: FACESET_OUTER_ID, face_tokens: faceToken });
}

// Lets the app tell people "username / number already used" BEFORE they go
// through the ID + selfie scan. Answers only those two yes/no questions.
const availabilityLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many attempts. Please try again later.' },
});

// ---------- registration / login (password, THEN pin) ----------

app.get('/api/register/check', availabilityLimiter, asyncRoute(async (req, res) => {
  const username = (req.query.username || '').toString().trim();
  const phone = (req.query.phone || '').toString().trim();
  let usernameTaken = false;
  let phoneTaken = false;
  if (username) {
    const [rows] = await pool.execute('SELECT id FROM users WHERE username = ?', [username]);
    usernameTaken = rows.length > 0;
  }
  if (phone) {
    const [rows] = await pool.execute('SELECT id FROM users WHERE phone_number = ? OR wallet_id = ?', [phone, phone]);
    phoneTaken = rows.length > 0;
  }
  res.json({ usernameTaken, phoneTaken });
}));

// Per-IP cap on sign-ups, on top of the per-username limit (which an attacker
// could dodge by changing the username every time).
const registerIpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many sign-up attempts from this network. Please try again later.' },
});

// ~4.5 MB of image per photo. Checks the size and that the bytes really are a
// JPEG / PNG / WebP image (not some other file dressed up as a photo).
const MAX_PHOTO_BASE64_CHARS = 6_000_000;
function looksLikeImage(b64) {
  if (typeof b64 !== 'string' || b64.length < 100 || b64.length > MAX_PHOTO_BASE64_CHARS) return false;
  const head = Buffer.from(b64.slice(0, 32), 'base64');
  const jpeg = head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff;
  const png = head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47;
  const webp = head.toString('latin1', 0, 4) === 'RIFF' && head.toString('latin1', 8, 12) === 'WEBP';
  return jpeg || png || webp;
}

// Set KEEP_ID_PHOTOS=true in Railway to keep ID photos after a decision.
const KEEP_ID_PHOTOS = process.env.KEEP_ID_PHOTOS === 'true';

app.post('/api/register', registerIpLimiter, authLimiter, asyncRoute(async (req, res) => {
   const {
    username, password, pin, phoneNumber,
    termsAccepted, governmentIdNumber,
    governmentIdPhotoFrontBase64, governmentIdPhotoBackBase64, selfiePhotoBase64,
  } = req.body || {};

  if (!username || !password || !pin || !phoneNumber) {
    return res.status(400).json({ error: 'username, password, pin, and phoneNumber are required' });
  }
  if ([username, password, pin, phoneNumber].some((v) => typeof v !== 'string')) {
    return res.status(400).json({ error: 'Invalid request' });
  }
  if (!/^[A-Za-z0-9_. -]{3,30}$/.test(username.trim())) {
    return res.status(400).json({ error: 'Username must be 3-30 characters: letters, numbers, spaces, . _ -' });
  }
  if (password.length > 72) return res.status(400).json({ error: 'Password must be 72 characters or fewer' });
  // Same rules as the app's checklist: 8+ chars, a letter, a number, and one of @ * _ -
  if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password) || !/[@*_-]/.test(password)) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters and include a letter, a number, and one of @ * _ -',
    });
  }
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
  if (!/^09\d{9}$/.test(phoneNumber)) {
    return res.status(400).json({ error: 'Phone number must be 11 digits starting with 09 (e.g. 09171234567)' });
  }
  if (!termsAccepted) {
    return res.status(400).json({ error: 'You must accept the Terms and Conditions to register' });
  }
  if (!governmentIdNumber || !governmentIdNumber.toString().trim()) {
    return res.status(400).json({ error: 'A government-issued ID number is required' });
  }
  if (
    !looksLikeImage(governmentIdPhotoFrontBase64) ||
    !looksLikeImage(governmentIdPhotoBackBase64) ||
    !looksLikeImage(selfiePhotoBase64)
  ) {
    return res.status(400).json({ error: 'The ID and selfie photos must be JPEG or PNG images under about 4 MB each' });
  }
  if (!governmentIdPhotoFrontBase64 || !governmentIdPhotoBackBase64 || !selfiePhotoBase64) {
    return res.status(400).json({ error: 'Photos of the front and back of your ID, plus a live selfie, are required' });
  }

  // Same ID written differently ("ab-123 456" vs "AB123456") must count as one.
  const normalizedId = governmentIdNumber.toString().toUpperCase().replace(/[\s-]/g, '');

  const conn = await pool.getConnection();
  try {
    if (usersByUsername.has(username)) {
      return res.status(409).json({ error: 'That username is already taken' });
    }
    const [existingUsername] = await conn.execute('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsername.length > 0) return res.status(409).json({ error: 'That username is already taken' });

    const [existingPhone] = await conn.execute('SELECT id FROM users WHERE phone_number = ?', [phoneNumber]);
    if (existingPhone.length > 0) {
      return res.status(409).json({ error: 'That phone number is already registered to an account' });
    }

    const [existingId] = await conn.execute(
      "SELECT id FROM users WHERE REPLACE(REPLACE(UPPER(government_id_number), ' ', ''), '-', '') = ?",
      [normalizedId]
    );
    if (existingId.length > 0) {
      return res.status(409).json({ error: 'That government ID is already registered to an account' });
    }

    // One face = one account: search the new selfie against every selfie
    // already registered. Skipped (not blocked) if Face++ is unavailable.
    let selfieFaceToken = null;
    if (FACEPP_API_KEY && FACEPP_API_SECRET) {
      try {
        await ensureFaceSet();
        selfieFaceToken = await detectFaceToken(selfiePhotoBase64);
        const duplicateFace = await findDuplicateFace(selfieFaceToken);
        if (duplicateFace) {
          return res.status(409).json({ error: 'This face is already registered to another account' });
        }
      } catch (err) {
        console.error('Duplicate-face check skipped:', err.message);
        selfieFaceToken = null;
      }
    }

    // Face match: compares the live selfie against the photo on the ID. This
    // only confirms the selfie matches THIS ID photo; the duplicate-face search
    // just above is what stops the same face registering under another account.
    let confidence = null;
    let verificationStatus = 'pending';
    try {
       const result = await compareFaces(governmentIdPhotoFrontBase64, selfiePhotoBase64);
      confidence = result.confidence;
      verificationStatus = result.matched ? 'approved' : 'pending';
    } catch (err) {
      // Face++ failure (bad image, no face detected, API error) does NOT
      // block registration — it just leaves the account pending for an
      // admin to review manually, same as a low-confidence score would.
      console.error('Face comparison failed during registration:', err.message);
      verificationStatus = 'pending';
    }

    // Only a sign-up confirmed with a real fingerprint touch may be approved
    // automatically. Phones with just a screen lock, no lock, or a browser go
    // to an admin even if the face matched. (This is what the app reports; a
    // modified app could claim 'fingerprint', so it is a safeguard, not proof.)
    const verificationMethod = typeof req.body?.verificationMethod === 'string' ? req.body.verificationMethod : 'none';
    if (verificationMethod !== 'fingerprint' && verificationStatus === 'approved') {
      verificationStatus = 'pending';
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const pinHash = await bcrypt.hash(pin, 10);
    const walletId = phoneNumber;

    let result;
    try {
      [result] = await conn.execute(
      `INSERT INTO users
         (username, password_hash, pin_hash, wallet_id, balance, phone_number,
          government_id_number, government_id_photo, government_id_photo_back, selfie_photo,
          terms_accepted_at, verification_status, face_match_confidence)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?)`,
      [
        username, passwordHash, pinHash, walletId, 0, phoneNumber,
        normalizedId, encryptPhoto(governmentIdPhotoFrontBase64), encryptPhoto(governmentIdPhotoBackBase64), encryptPhoto(selfiePhotoBase64),
        verificationStatus, confidence,
      ]
    );
    } catch (err) {
      // Two sign-ups racing each other can both pass the SELECT checks above;
      // the database's UNIQUE keys (see sql/add_unique_constraints.sql) catch that.
      if (err.code === 'ER_DUP_ENTRY') {
        const m = err.sqlMessage || '';
        const msg = /phone|wallet/i.test(m)
          ? 'That phone number is already registered to an account'
          : /government|gov_id/i.test(m)
            ? 'That government ID is already registered to an account'
            : 'That username is already taken';
        return res.status(409).json({ error: msg });
      }
      throw err;
    }

    if (selfieFaceToken) {
      try {
        await addFaceToIndex(selfieFaceToken);
      } catch (err) {
        console.error('Could not add face to index:', err.message);
      }
    }

    if (verificationStatus === 'approved' && !KEEP_ID_PHOTOS) {
      await conn.execute(
        "UPDATE users SET government_id_photo = '', government_id_photo_back = '', selfie_photo = '' WHERE id = ?",
        [result.insertId]
      );
    }

    await refreshUserInIndex(result.insertId);

    res.json({
      ok: true,
      walletId,
      verificationStatus,
      message: verificationStatus === 'approved'
        ? 'Account verified — you can log in now.'
        : 'Account created. Your ID is pending verification by an admin before you can log in.',
    });
  } finally {
    conn.release();
  }
}));

// Step 1: password only. Returns a short-lived "pending" token that is
// NOT enough to call any authenticated endpoint — it only unlocks the
// pin-verify step below.
app.post('/api/login', authLimiter, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

  const identifier = `login:${username.toString().trim().toLowerCase()}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

        const [rows] = await pool.execute(
    'SELECT id, password_hash, status, verification_status FROM users WHERE username = ?',
    [username]
  );
  const user = rows[0];
  // Always run bcrypt, even when the username doesn't exist, so a lookup
  // miss takes the same time as a real-but-wrong-password attempt —
  // otherwise the instant-return-on-miss path leaks which usernames are
  // registered via response timing.
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_BCRYPT_HASH);
  if (!user || !ok) {
    await recordFailedAttempt(identifier);
    return res.status(401).json({ error: 'Incorrect username or password' });
  }
  // Checked AFTER password verification (not before) so a wrong-password
  // attempt against a suspended account still just says "incorrect
  // username or password" — it doesn't leak account status to a guesser.
  if (user.status === 'suspended') {
    return res.status(403).json({ error: 'This account has been suspended. Contact support for assistance.' });
  }
  if (user.verification_status === 'pending') {
    return res.status(403).json({ error: 'Your account is still pending ID verification. Please check back later.' });
  }
  if (user.verification_status === 'rejected') {
    return res.status(403).json({ error: 'Your ID verification was not approved. Contact support for assistance.' });
  }
  await clearAttempts(identifier);

  const pendingToken = sign({ uid: user.id, stage: 'pending', role: 'user' }, '5m');
  res.json({ pendingToken });
}));

// Step 2: the PIN, checked separately from the password. Only after this
// succeeds does the client get a token any other endpoint will accept.
app.post('/api/login/verify-pin', pinLimiter, asyncRoute(async (req, res) => {
  const { pendingToken, pin } = req.body || {};
  const payload = pendingToken && verify(pendingToken);
  if (!payload || payload.stage !== 'pending' || payload.role !== 'user') {
    return res.status(401).json({ error: 'Login session expired, please log in again' });
  }

  const identifier = `pin:${payload.uid}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

  const [rows] = await pool.execute('SELECT id, username, wallet_id, pin_hash, balance FROM users WHERE id = ?', [
    payload.uid,
  ]);
  const user = rows[0];
  const ok = await bcrypt.compare(pin, user ? user.pin_hash : DUMMY_BCRYPT_HASH);
  if (!user || !ok) {
    await recordFailedAttempt(identifier);
    return res.status(401).json({ error: 'Incorrect PIN' });
  }
  await clearAttempts(identifier);

  const token = sign({ uid: user.id, stage: 'full', role: 'user' }, '2h');
  res.json({
    token,
    // balance is returned as an integer count of centavos — the client
    // divides by 100 only when displaying it.
    user: { id: user.id, username: user.username, walletId: user.wallet_id, balance: toCentavos(user.balance) },
  });
}));

// ---------- fingerprint / device login ----------
// After a normal login the person can switch on "fingerprint login" in the
// app. The server then gives that phone a random device token (only its
// SHA-256 hash is stored here). The phone keeps the token in its secure
// keystore and only reveals it after a fingerprint check. Logging in with it
// gives a normal 2-hour session without typing password + PIN. The token is
// replaced with a fresh one on every use, expires after 30 days of not being
// used, and can be revoked. Money actions still ask for the PIN.
const DEVICE_TOKEN_DAYS = 30;
const MAX_DEVICES_PER_USER = 5;
const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');

const deviceLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => ipKeyGenerator(req),
  message: { error: 'Too many attempts. Please try again later.' },
});

app.post('/api/device/enroll', requireAuth, moneyLimiter, requirePin, asyncRoute(async (req, res) => {
  const deviceName = cleanText(req.body?.deviceName, 100) || 'Phone';

  // Keep at most MAX_DEVICES_PER_USER phones: drop the oldest ones.
  const [existing] = await pool.execute('SELECT id FROM device_tokens WHERE user_id = ? ORDER BY created_at DESC', [req.userId]);
  if (existing.length >= MAX_DEVICES_PER_USER) {
    const dropIds = existing.slice(MAX_DEVICES_PER_USER - 1).map((r) => r.id);
    await pool.query('DELETE FROM device_tokens WHERE id IN (?)', [dropIds]);
  }

  const deviceToken = crypto.randomBytes(32).toString('hex');
  await pool.execute(
    'INSERT INTO device_tokens (user_id, token_hash, device_name, expires_at) VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? DAY))',
    [req.userId, sha256(deviceToken), deviceName, DEVICE_TOKEN_DAYS]
  );
  res.json({ deviceToken });
}));

app.post('/api/login/device', deviceLoginLimiter, asyncRoute(async (req, res) => {
  const expired = { error: 'Fingerprint login expired. Please log in with your password.' };
  const deviceToken = req.body?.deviceToken;
  if (typeof deviceToken !== 'string' || !/^[0-9a-f]{64}$/.test(deviceToken)) {
    return res.status(401).json(expired);
  }
  const oldHash = sha256(deviceToken);
  const [[row]] = await pool.query(
    `SELECT d.id AS device_id, u.id, u.username, u.wallet_id, u.balance, u.status, u.verification_status
       FROM device_tokens d JOIN users u ON u.id = d.user_id
      WHERE d.token_hash = ? AND d.expires_at > NOW()`,
    [oldHash]
  );
  if (!row) return res.status(401).json(expired);
  if (row.status === 'suspended') {
    return res.status(403).json({ error: 'This account has been suspended. Contact support for assistance.' });
  }
  if (row.verification_status !== 'approved') {
    return res.status(403).json({ error: 'Your account is not verified. Please log in with your password.' });
  }

  // Swap in a new token. The WHERE on the old hash means an old token that was
  // already used (replayed, or raced) matches nothing and is refused.
  const newToken = crypto.randomBytes(32).toString('hex');
  const [swap] = await pool.execute(
    'UPDATE device_tokens SET token_hash = ?, last_used_at = NOW(), expires_at = DATE_ADD(NOW(), INTERVAL ? DAY) WHERE id = ? AND token_hash = ?',
    [sha256(newToken), DEVICE_TOKEN_DAYS, row.device_id, oldHash]
  );
  if (swap.affectedRows !== 1) return res.status(401).json(expired);

  res.json({
    token: sign({ uid: row.id, stage: 'full', role: 'user' }, '2h'),
    deviceToken: newToken,
    user: { id: row.id, username: row.username, walletId: row.wallet_id, balance: toCentavos(row.balance) },
  });
}));

// Turn fingerprint login off for this phone (or all phones if no token is sent).
app.post('/api/device/revoke', requireAuth, asyncRoute(async (req, res) => {
  const deviceToken = req.body?.deviceToken;
  if (typeof deviceToken === 'string' && /^[0-9a-f]{64}$/.test(deviceToken)) {
    await pool.execute('DELETE FROM device_tokens WHERE user_id = ? AND token_hash = ?', [req.userId, sha256(deviceToken)]);
  } else {
    await pool.execute('DELETE FROM device_tokens WHERE user_id = ?', [req.userId]);
  }
  res.json({ ok: true });
}));

app.get('/api/me', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute('SELECT id, username, wallet_id, balance FROM users WHERE id = ?', [req.userId]);
  if (!rows[0]) return res.status(404).json({ error: 'User not found' });
  const u = rows[0];
  res.json({ id: u.id, username: u.username, wallet_id: u.wallet_id, balance: toCentavos(u.balance) });
}));

// ---------- wallet-to-wallet (QR) payment ----------

app.post('/api/wallet/pay', requireAuth, moneyLimiter, requirePin, asyncRoute(async (req, res) => {
  const { walletId, amountCentavos } = req.body || {};
  const amt = parseCentavos(amountCentavos);
  if (!walletId || amt === null) {
    return res.status(400).json({ error: 'walletId and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[found]] = await conn.query('SELECT id FROM users WHERE wallet_id = ?', [walletId]);
    const lockIds = [req.userId, ...(found ? [found.id] : [])].sort((a, b) => a - b);
    await conn.query(`SELECT id FROM users WHERE id IN (${lockIds.map(() => '?').join(',')}) ORDER BY id FOR UPDATE`, lockIds);
    const [[sender]] = await conn.query('SELECT id, balance FROM users WHERE id = ?', [req.userId]);
    const [[recipient]] = found
      ? await conn.query('SELECT id, username, balance FROM users WHERE id = ?', [found.id])
      : [[undefined]];

    if (!recipient) {
      await conn.rollback();
      return res.status(404).json({ error: 'No account found for that Wallet ID' });
    }
    if (recipient.id === sender.id) {
      await conn.rollback();
      return res.status(400).json({ error: "You can't pay your own Wallet ID" });
    }

    const senderBalance = toCentavos(sender.balance);
    if (senderBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const transferRef = crypto.randomUUID();
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, sender.id]);
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, recipient.id]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref) VALUES (?,?,?,?,?,?,?)',
      ['user', sender.id, `QR Payment to ${recipient.username}`, 'QR Payment', amt, 0, transferRef]
    );
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref) VALUES (?,?,?,?,?,?,?)',
      ['user', recipient.id, `QR Payment from user #${sender.id}`, 'QR Payment', amt, 1, transferRef]
    );

    await conn.commit();

    // Row is committed — now safe to refresh both cached users so the
    // hash-map indexes don't serve a stale balance (item #6 fix).
    await Promise.all([
      refreshUserInIndex(sender.id),
      refreshUserInIndex(recipient.id),
    ]);

    getUndoStack(sender.id).push({ ref: transferRef, at: Date.now() }); // NEW — item: mandatory "Stack"

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- personal-account actions (restored) ----------

// Lets the app check a PIN in its confirm dialog (and show "Incorrect PIN")
// before starting a payment. The payment routes still verify the PIN themselves.
app.post('/api/pin/check', requireAuth, moneyLimiter, requirePin, (req, res) => res.json({ ok: true }));

app.get('/api/notifications', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT id, label AS title, type, amount, is_credit AS isCredit, created_at AS createdAt
     FROM transactions
     WHERE account_type = 'user' AND account_id = ?
     ORDER BY created_at DESC
     LIMIT 20`,
    [req.userId]
  );
  res.json(rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })));
}));

app.post('/api/send', requireAuth, moneyLimiter, requirePin, asyncRoute(async (req, res) => {
  const recipient = req.body?.recipient?.toString().trim();
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!recipient || amt === null) {
    return res.status(400).json({ error: 'recipient and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[found]] = await conn.query('SELECT id FROM users WHERE wallet_id = ?', [recipient]);
    const lockIds = [req.userId, ...(found ? [found.id] : [])].sort((a, b) => a - b);
    await conn.query(`SELECT id FROM users WHERE id IN (${lockIds.map(() => '?').join(',')}) ORDER BY id FOR UPDATE`, lockIds);
    const [[sender]] = await conn.query('SELECT id, balance FROM users WHERE id = ?', [req.userId]);
    const [[recipientUser]] = found
      ? await conn.query('SELECT id, username, balance FROM users WHERE id = ?', [found.id])
      : [[undefined]];

    // ---- unchanged ----
    if (!recipientUser) {
      await conn.rollback();
      return res.status(404).json({ error: 'No account found for that Wallet ID' });
    }
    if (recipientUser.id === sender.id) {
      await conn.rollback();
      return res.status(400).json({ error: "You can't send money to your own Wallet ID" });
    }

    const senderBalance = toCentavos(sender.balance);
    if (senderBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    // ---- end unchanged ----

    const transferRef = crypto.randomUUID();
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, sender.id]);
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, recipientUser.id]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref) VALUES (?,?,?,?,?,?,?)',
      ['user', sender.id, `Sent to ${recipientUser.username}`, 'Send Money', amt, 0, transferRef]
    );
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref) VALUES (?,?,?,?,?,?,?)',
      ['user', recipientUser.id, `Received from user #${sender.id}`, 'Send Money', amt, 1, transferRef]
    );

    await conn.commit();

    // <-- NEW: only line added to this whole route
    await Promise.all([
      refreshUserInIndex(sender.id),
      refreshUserInIndex(recipientUser.id),
    ]);

    getUndoStack(sender.id).push({ ref: transferRef, at: Date.now() }); // NEW — item: mandatory "Stack"

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/load', requireAuth, moneyLimiter, requirePin, asyncRoute(async (req, res) => {
  const { number, network } = req.body || {};
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!number || !network || amt === null) {
    return res.status(400).json({ error: 'number, network, and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[user]] = await conn.query('SELECT id, balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const userBalance = toCentavos(user.balance);
    if (userBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

     await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Mobile Load to ${number}`, 'Load', amt, 0]
    );

    await conn.commit();

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/bills/pay', requireAuth, moneyLimiter, requirePin, asyncRoute(async (req, res) => {
  const biller = req.body?.biller?.toString().trim();
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!biller || amt === null) {
    return res.status(400).json({ error: 'biller and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[user]] = await conn.query('SELECT id, balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const userBalance = toCentavos(user.balance);
    if (userBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Bill Pay to ${biller}`, 'Bill Payment', amt, 0]
    );

    await conn.commit();

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.get('/api/transactions', requireAuth, asyncRoute(async (req, res) => {
  const [[me]] = await pool.query('SELECT username FROM users WHERE id = ?', [req.userId]);
  const [groupRows] = await pool.execute(
    'SELECT g.id, g.name FROM group_members gm JOIN `groups` g ON g.id = gm.group_id WHERE gm.user_id = ?',
    [req.userId]
  );
  const groupNameById = Object.fromEntries(groupRows.map((g) => [g.id, g.name]));
  const groupIds = groupRows.map((g) => g.id);

  let rows;
  if (groupIds.length > 0) {
    const placeholders = groupIds.map(() => '?').join(',');
    const [result] = await pool.query(
      `SELECT id, account_type, account_id, label, type, amount, is_credit AS isCredit, created_at AS createdAt
       FROM transactions
       WHERE (account_type = 'user' AND account_id = ?)
          OR (account_type = 'group' AND account_id IN (${placeholders}))`,
      [req.userId, ...groupIds]
    );
    rows = result;
  } else {
    const [result] = await pool.execute(
      `SELECT id, account_type, account_id, label, type, amount, is_credit AS isCredit, created_at AS createdAt
       FROM transactions WHERE account_type = 'user' AND account_id = ?`,
      [req.userId]
    );
    rows = result;
  }

  const normalized = rows.map((row) => ({
    ...row,
    amount: toCentavos(row.amount),
    accountName: row.account_type === 'user' ? me.username : groupNameById[row.account_id] || 'Group',
  }));

  const sorted = mergeSort(normalized, comparators.dateDesc);

  res.json(sorted);
}));

app.get('/api/groups/mine', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT g.id, g.name, g.balance,
            (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.group_id = g.id) AS memberCount
     FROM \`groups\` g
     JOIN group_members gm ON gm.group_id = g.id
     WHERE gm.user_id = ?`,
    [req.userId]
  );
  res.json(rows.map((g) => ({ ...g, balance: toCentavos(g.balance) })));
}));

app.get('/api/groups', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT g.id, g.name, g.balance,
            (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.group_id = g.id) AS memberCount
     FROM \`groups\` g
     ORDER BY g.name ASC`
  );
  res.json(rows.map((g) => ({ ...g, balance: toCentavos(g.balance) })));
}));

// Shared by every /api/groups/:id... route below: confirms req.userId is
// actually a member of groupId before any group-internal data (balance,
// transactions, member list w/ wallet IDs, requests) is returned. Without
// this, any authenticated user could read any group's data just by
// guessing/incrementing IDs — group membership, not just login, is the
// access boundary here.
async function requireGroupMembership(groupId, userId) {
  const [[membership]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, userId]
  );
  return !!membership;
}

app.get('/api/groups/:id', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!Number.isInteger(groupId)) {
    return res.status(400).json({ error: 'Invalid group ID' });
  }
  if (!(await requireGroupMembership(groupId, req.userId))) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }
  const [[group]] = await pool.query('SELECT id, name, balance FROM `groups` WHERE id = ?', [groupId]);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  const [members] = await pool.execute(
    `SELECT u.id, u.username, u.wallet_id AS walletId
     FROM group_members gm JOIN users u ON u.id = gm.user_id
     WHERE gm.group_id = ?`,
    [groupId]
  );
  res.json({ id: group.id, name: group.name, balance: toCentavos(group.balance), members });
}));

app.get('/api/groups/:id/transactions', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!Number.isInteger(groupId)) {
    return res.status(400).json({ error: 'Invalid group ID' });
  }
  if (!(await requireGroupMembership(groupId, req.userId))) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }
  const [rows] = await pool.execute(
    `SELECT id, label, type, amount, is_credit AS isCredit, created_at AS createdAt
     FROM transactions
     WHERE account_type = 'group' AND account_id = ?
     ORDER BY created_at DESC`,
    [groupId]
  );
  res.json(rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })));
}));

app.get('/api/groups/:id/requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!(await requireGroupMembership(groupId, req.userId))) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }
  const [rows] = await pool.execute(
    `SELECT id, requester_name AS requesterName, reason, amount, status, created_at AS createdAt
     FROM withdrawal_requests
     WHERE group_id = ?
     ORDER BY created_at DESC`,
    [groupId]
  );
  res.json(rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })));
}));

app.post('/api/groups/:id/withdraw-requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  const reason = cleanText(req.body?.reason, 255) || null;
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [members] = await conn.query(
      'SELECT user_id FROM group_members WHERE group_id = ?',
      [groupId]
    );
    if (!members.some((m) => m.user_id === req.userId)) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    const [[group]] = await conn.query('SELECT balance FROM `groups` WHERE id = ?', [groupId]);
    if (toCentavos(group.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient group balance' });
    }

    // majority = more than half of current members
    const approvalsNeeded = Math.floor(members.length / 2) + 1;

    const [result] = await conn.execute(
      'INSERT INTO group_withdraw_requests (group_id, requester_id, amount, reason, approvals_needed) VALUES (?,?,?,?,?)',
      [groupId, req.userId, amt, reason, approvalsNeeded]
    );

    await conn.commit();
    res.json({ id: result.insertId, ok: true, approvalsNeeded });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.get('/api/groups/:id/withdraw-requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);

  const [[membership]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const [rows] = await pool.execute(
    `SELECT wr.id, wr.requester_id AS requesterId, u.username AS requesterName,
            wr.amount, wr.reason, wr.status, wr.approvals_needed AS approvalsNeeded,
            (SELECT COUNT(*) FROM group_withdraw_approvals wa WHERE wa.request_id = wr.id AND wa.decision = 'approve') AS approvalsCount,
            EXISTS(SELECT 1 FROM group_withdraw_approvals wa WHERE wa.request_id = wr.id AND wa.member_id = ?) AS decidedByMe
     FROM group_withdraw_requests wr JOIN users u ON u.id = wr.requester_id
     WHERE wr.group_id = ? AND wr.status = 'pending'
     ORDER BY wr.created_at DESC`,
    [req.userId, groupId]
  );
  res.json(rows.map((r) => ({ ...r, amount: toCentavos(r.amount) })));
}));
// ---------- groups (capped at MAX_GROUP_MEMBERS) ----------

app.post('/api/groups', requireAuth, asyncRoute(async (req, res) => {
  const name = cleanText(req.body?.name, 100);
  if (!name) return res.status(400).json({ error: 'name is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [result] = await conn.execute('INSERT INTO `groups` (name) VALUES (?)', [name]);
    await conn.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', [result.insertId, req.userId]);
    await conn.commit();
    res.json({ id: result.insertId, name });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:id/request-join', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);

  const [[already]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, req.userId]
  );
  if (already) return res.status(409).json({ error: 'Already a member' });

  const [[pending]] = await pool.query(
    "SELECT 1 FROM group_join_requests WHERE group_id = ? AND user_id = ? AND status = 'pending'",
    [groupId, req.userId]
  );
  if (pending) return res.status(409).json({ error: 'Request already pending' });

  await pool.execute(
    'INSERT INTO group_join_requests (group_id, user_id) VALUES (?, ?)',
    [groupId, req.userId]
  );
  res.json({ ok: true });
}));

app.get('/api/groups/:id/join-requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const [[membership]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const [rows] = await pool.execute(
    `SELECT jr.id, jr.user_id AS userId, u.username, jr.created_at AS createdAt
     FROM group_join_requests jr JOIN users u ON u.id = jr.user_id
     WHERE jr.group_id = ? AND jr.status = 'pending'`,
    [groupId]
  );
  res.json(rows);
}));

app.post('/api/groups/:groupId/join-requests/:reqId/respond', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.groupId);
  const reqId = Number(req.params.reqId);
  const approve = !!req.body?.approve;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[membership]] = await conn.query(
      'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
      [groupId, req.userId]
    );
    if (!membership) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    const [[request]] = await conn.query(
      "SELECT * FROM group_join_requests WHERE id = ? AND group_id = ? AND status = 'pending' FOR UPDATE",
      [reqId, groupId]
    );
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Request not found or already decided' });
    }

    if (approve) {
      const [members] = await conn.query(
        'SELECT user_id FROM group_members WHERE group_id = ? FOR UPDATE',
        [groupId]
      );
      if (members.length >= MAX_GROUP_MEMBERS) {
        await conn.rollback();
        return res.status(409).json({ error: `Group is full (max ${MAX_GROUP_MEMBERS})` });
      }
      await conn.execute(
        'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
        [groupId, request.user_id]
      );
    }

    await conn.execute(
      'UPDATE group_join_requests SET status = ? WHERE id = ?',
      [approve ? 'approved' : 'declined', reqId]
    );

    await conn.commit();
    res.json({ ok: true, status: approve ? 'approved' : 'declined' });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:groupId/withdraw-requests/:reqId/respond', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.groupId);
  const reqId = Number(req.params.reqId);
  const approve = !!req.body?.approve;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[membership]] = await conn.query(
      'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
      [groupId, req.userId]
    );
    if (!membership) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    const [[request]] = await conn.query(
      "SELECT * FROM group_withdraw_requests WHERE id = ? AND group_id = ? AND status = 'pending' FOR UPDATE",
      [reqId, groupId]
    );
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Request not found or already decided' });
    }

    const [[already]] = await conn.query(
      'SELECT 1 FROM group_withdraw_approvals WHERE request_id = ? AND member_id = ?',
      [reqId, req.userId]
    );
    if (already) {
      await conn.rollback();
      return res.status(409).json({ error: 'You already voted on this request' });
    }

    await conn.execute(
      'INSERT INTO group_withdraw_approvals (request_id, member_id, decision) VALUES (?,?,?)',
      [reqId, req.userId, approve ? 'approve' : 'decline']
    );

    if (!approve) {
      await conn.execute("UPDATE group_withdraw_requests SET status = 'declined' WHERE id = ?", [reqId]);
      await conn.commit();
      return res.json({ ok: true, status: 'declined' });
    }

    const [[{ approvals }]] = await conn.query(
      "SELECT COUNT(*) AS approvals FROM group_withdraw_approvals WHERE request_id = ? AND decision = 'approve'",
      [reqId]
    );

    if (approvals >= request.approvals_needed) {
      const amt = toCentavos(request.amount);

      const [[group]] = await conn.query('SELECT balance FROM `groups` WHERE id = ? FOR UPDATE', [groupId]);
      if (toCentavos(group.balance) < amt) {
        await conn.rollback();
        return res.status(400).json({ error: 'Group balance too low to complete this withdrawal now' });
      }

      await conn.execute('UPDATE `groups` SET balance = balance - ? WHERE id = ?', [amt, groupId]);
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, request.requester_id]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
        ['group', groupId, `Withdrawal to user #${request.requester_id} (approved)`, 'Group Withdrawal', amt, 0]
      );
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
        ['user', request.requester_id, `Group withdrawal from #${groupId}`, 'Group Withdrawal', amt, 1]
      );
      await conn.execute("UPDATE group_withdraw_requests SET status = 'approved' WHERE id = ?", [reqId]);

      await conn.commit();
      await refreshUserInIndex(request.requester_id);
      return res.json({ ok: true, status: 'approved', executed: true });
    }

    await conn.commit();
    res.json({ ok: true, status: 'pending', approvalsCount: approvals, approvalsNeeded: request.approvals_needed });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:id/contribute', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[membership]] = await conn.query('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', [
      groupId,
      req.userId,
    ]);
    if (!membership) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }
    const [[user]] = await conn.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    if (toCentavos(user.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute('UPDATE `groups` SET balance = balance + ? WHERE id = ?', [amt, groupId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['group', groupId, `Contribution from user #${req.userId}`, 'Contribution', amt, 1]
    );
    await conn.commit();

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:id/requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const { requesterName, reason, amountCentavos } = req.body || {};
  const amt = parseCentavos(amountCentavos);
  if (!requesterName || !reason || amt === null) {
    return res.status(400).json({ error: 'requesterName, reason, and a positive amount (integer centavos) are required' });
  }
  // A member-only gate: approving one of these debits the group balance
  // directly (see /api/admin/groups/:groupId/requests/:reqId/respond),
  // with no recipient account tied to the request — so without this
  // check, anyone with a login (member or not) could plant a request
  // against an arbitrary group and rely on an admin approving it based
  // on the free-text requesterName/reason alone.
  if (!(await requireGroupMembership(groupId, req.userId))) {
    return res.status(403).json({ error: 'Not a member of this group' });
  }
  await pool.execute(
    'INSERT INTO withdrawal_requests (group_id, requester_name, reason, amount) VALUES (?,?,?,?)',
    [groupId, requesterName, reason, amt]
  );
  res.json({ ok: true });
}));

// ---------- savings goals (personal, locked sub-balance) ----------

app.post('/api/savings', requireAuth, asyncRoute(async (req, res) => {
  const name = cleanText(req.body?.name, 100);
  const target = parseCentavos(req.body?.targetAmountCentavos);
  if (!name) return res.status(400).json({ error: 'A goal name is required' });
  if (target === null) return res.status(400).json({ error: 'A positive target amount (integer centavos) is required' });

  const [result] = await pool.execute(
    'INSERT INTO savings_goals (user_id, name, target_amount) VALUES (?, ?, ?)',
    [req.userId, name, target]
  );
  res.json({ id: result.insertId, ok: true });
}));

app.get('/api/savings/mine', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT id, name, target_amount, saved_amount, status, created_at FROM savings_goals WHERE user_id = ? ORDER BY created_at DESC',
    [req.userId]
  );
  res.json(rows.map((g) => ({
    ...g,
    targetAmount: toCentavos(g.target_amount),
    savedAmount: toCentavos(g.saved_amount),
  })));
}));

app.post('/api/savings/:id/deposit', requireAuth, asyncRoute(async (req, res) => {
  const goalId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[goal]] = await conn.query(
      'SELECT * FROM savings_goals WHERE id = ? AND user_id = ? FOR UPDATE',
      [goalId, req.userId]
    );
    if (!goal) {
      await conn.rollback();
      return res.status(404).json({ error: 'Goal not found' });
    }
    const [[user]] = await conn.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    if (toCentavos(user.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const newSaved = toCentavos(goal.saved_amount) + amt;
    const nowComplete = newSaved >= toCentavos(goal.target_amount);

    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute('UPDATE savings_goals SET saved_amount = ?, status = ? WHERE id = ?', [
      newSaved, nowComplete ? 'completed' : 'active', goalId,
    ]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Savings: ${goal.name}`, 'Savings Deposit', amt, 0]
    );

    await conn.commit();
    await refreshUserInIndex(req.userId);
    res.json({ ok: true, savedAmount: newSaved, completed: nowComplete });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/savings/:id/withdraw', requireAuth, asyncRoute(async (req, res) => {
  const goalId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[goal]] = await conn.query(
      'SELECT * FROM savings_goals WHERE id = ? AND user_id = ? FOR UPDATE',
      [goalId, req.userId]
    );
    if (!goal) {
      await conn.rollback();
      return res.status(404).json({ error: 'Goal not found' });
    }
    const saved = toCentavos(goal.saved_amount);
    if (saved < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Not enough saved in this goal' });
    }

    const newSaved = saved - amt;
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, req.userId]);
    await conn.execute('UPDATE savings_goals SET saved_amount = ?, status = ? WHERE id = ?', [
      newSaved, 'active', goalId,
    ]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Savings withdrawal: ${goal.name}`, 'Savings Withdrawal', amt, 1]
    );

    await conn.commit();
    await refreshUserInIndex(req.userId);
    res.json({ ok: true, savedAmount: newSaved });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.delete('/api/savings/:id', requireAuth, asyncRoute(async (req, res) => {
  const goalId = Number(req.params.id);
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[goal]] = await conn.query(
      'SELECT * FROM savings_goals WHERE id = ? AND user_id = ? FOR UPDATE',
      [goalId, req.userId]
    );
    if (!goal) {
      await conn.rollback();
      return res.status(404).json({ error: 'Goal not found' });
    }
    const saved = toCentavos(goal.saved_amount);
    if (saved > 0) {
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [saved, req.userId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
        ['user', req.userId, `Closed goal: ${goal.name}`, 'Savings Withdrawal', saved, 1]
      );
    }
    await conn.execute('DELETE FROM savings_goals WHERE id = ?', [goalId]);
    await conn.commit();
    await refreshUserInIndex(req.userId);
    res.json({ ok: true, returnedCentavos: saved });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- admin: login + final say on groups (item #13) ----------

// Step 1: password only.
app.post('/api/admin/login', adminLimiter, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username is required' });

  const identifier = `admin:${username.toString().trim().toLowerCase()}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    await logAdminEvent(req, 'admin_login_locked', null, username);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

  const [rows] = await pool.execute('SELECT id, password_hash, pin_hash FROM admins WHERE username = ?', [username]);
  const admin = rows[0];
  const ok = await bcrypt.compare(password || '', admin ? admin.password_hash : DUMMY_BCRYPT_HASH);
  if (!admin || !ok) {
    await recordFailedAttempt(identifier);
    await logAdminEvent(req, 'admin_login_failed', admin ? admin.id : null, username);
    return res.status(401).json({ error: 'Incorrect admin credentials' });
  }
  if (!admin.pin_hash) {
    return res.status(403).json({
      error: 'This admin account has no PIN set yet. Run `npm run create-admin -- <username> <password> <pin>` to set one before logging in.',
    });
  }
  await clearAttempts(identifier);

  const pendingToken = sign({ uid: admin.id, stage: 'pending', role: 'admin' }, '5m');
  res.json({ pendingToken });
}));

// Step 2: the PIN.
app.post('/api/admin/login/verify-pin', adminPinLimiter, asyncRoute(async (req, res) => {
  const { pendingToken, pin } = req.body || {};
  const payload = pendingToken && verify(pendingToken);
  if (!payload || payload.stage !== 'pending' || payload.role !== 'admin') {
    return res.status(401).json({ error: 'Login session expired, please log in again' });
  }

  const identifier = `adminpin:${payload.uid}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    await logAdminEvent(req, 'admin_pin_locked', payload.uid, `admin ${payload.uid}`);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

  const [rows] = await pool.execute('SELECT id, pin_hash FROM admins WHERE id = ?', [payload.uid]);
  const admin = rows[0];
  const ok = await bcrypt.compare(pin || '', admin ? admin.pin_hash : DUMMY_BCRYPT_HASH);
  if (!admin || !ok) {
    await recordFailedAttempt(identifier);
    await logAdminEvent(req, 'admin_pin_failed', payload.uid, `admin ${payload.uid}`);
    return res.status(401).json({ error: 'Incorrect PIN' });
  }
  await clearAttempts(identifier);
  await logAdminEvent(req, 'admin_login', admin.id, `admin ${admin.id}`);

  const token = sign({ uid: admin.id, stage: 'full', role: 'admin' }, '4h');
  res.json({ token });
}));

// Full oversight view: every registered user, their balance/wallet, and
// how many groups they belong to.
app.get('/api/admin/users', requireAdmin, asyncRoute(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 50));
  const offset = (page - 1) * pageSize;
    const search = req.query.search ? `%${req.query.search.toString().trim()}%` : null;
  const sortBy = req.query.sortBy === 'balance' ? 'balance' : 'username';

  // Matches on username OR the numeric ID (cast to text so a partial-ID
  // search like "12" also matches id 12, 120, 1123, etc.) OR the wallet ID.
  const whereClause = search ? 'WHERE (u.username LIKE ? OR CAST(u.id AS CHAR) LIKE ? OR u.wallet_id LIKE ?)' : '';
  const params = search ? [search, search, search] : [];

  const [[{ total }]] = await pool.query(
    `SELECT COUNT(*) AS total FROM users u ${whereClause}`,
    params
  );

  // DB does the heavy lifting (only pulls the rows for this page) — merge
  // sort still runs, just on the bounded page instead of the whole table,
  // so it stays fast at any scale while keeping the mandatory sort step.
      const [rawUsers] = await pool.query(
    `SELECT u.id, u.username, u.wallet_id AS walletId, u.balance, u.status,
            (SELECT COUNT(*) FROM group_members gm WHERE gm.user_id = u.id) AS groupCount
     FROM users u
     ${whereClause}
     LIMIT ? OFFSET ?`,
    [...params, pageSize, offset]
  );

  const normalized = rawUsers.map((u) => ({ ...u, balance: toCentavos(u.balance) }));
  const sorted =
    sortBy === 'balance'
      ? mergeSort(normalized, comparators.balanceDesc)
      : mergeSort(normalized, comparators.usernameAsc);

  res.json({
    users: sorted,
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize)),
  });
}));

// Admin suspends or reactivates a user's account. Suspension blocks login
// at the password step (before a session token can even be issued) but
// doesn't touch existing data — balance, groups, and loan history stay
// intact so reactivating just picks back up where things left off.
app.post('/api/admin/users/:id/status', requireAdmin, asyncRoute(async (req, res) => {
  const userId = Number(req.params.id);
  const suspend = !!req.body?.suspend;
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const [result] = await pool.execute('UPDATE users SET status = ? WHERE id = ?', [
    suspend ? 'suspended' : 'active',
    userId,
  ]);
  if (result.affectedRows === 0) {
    return res.status(404).json({ error: 'User not found' });
  }

  await refreshUserInIndex(userId);
  await logAdmin(req, suspend ? 'suspend_user' : 'unsuspend_user', 'user', userId);
  res.json({ ok: true, status: suspend ? 'suspended' : 'active' });
}));


// Purchase/transaction history for one specific user — powers the
// "View Purchases" button next to each row in the admin Users tab.
app.get('/api/admin/users/:id/transactions', requireAdmin, asyncRoute(async (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isInteger(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 20));
  const offset = (page - 1) * pageSize;

  const [[user]] = await pool.query('SELECT id, username FROM users WHERE id = ?', [userId]);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const [[{ total }]] = await pool.query(
    "SELECT COUNT(*) AS total FROM transactions WHERE account_type = 'user' AND account_id = ?",
    [userId]
  );

  const [rows] = await pool.query(
    `SELECT id, label, type, amount, is_credit AS isCredit, created_at AS createdAt
     FROM transactions
     WHERE account_type = 'user' AND account_id = ?
     ORDER BY created_at DESC
     LIMIT ? OFFSET ?`,
    [userId, pageSize, offset]
  );

  const transactions = rows.map((t) => ({ ...t, amount: toCentavos(t.amount) }));

  res.json({
    username: user.username,
    transactions,
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize)),
  });
}));

// Full oversight view: every group with its members and pending requests.
app.get('/api/admin/groups', requireAdmin, asyncRoute(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 50));
  const offset = (page - 1) * pageSize;
  const search = req.query.search ? `%${req.query.search.toString().trim()}%` : null;
  const whereClause = search ? 'WHERE name LIKE ?' : '';
  const params = search ? [search] : [];

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total FROM \`groups\` ${whereClause}`, params);

  const [groups] = await pool.query(
    `SELECT id, name, balance FROM \`groups\` ${whereClause} ORDER BY name ASC LIMIT ? OFFSET ?`,
    [...params, pageSize, offset]
  );

  for (const g of groups) {
    g.balance = toCentavos(g.balance);
    const [members] = await pool.execute(
      `SELECT u.id, u.username, u.wallet_id AS walletId
       FROM group_members gm JOIN users u ON u.id = gm.user_id
       WHERE gm.group_id = ?`,
      [g.id]
    );
    const [requests] = await pool.execute(
      `SELECT id, requester_name AS requesterName, reason, amount, status
       FROM withdrawal_requests WHERE group_id = ? AND status = 'pending'`,
      [g.id]
    );
    g.members = members;
    g.pendingRequests = requests.map((r) => ({ ...r, amount: toCentavos(r.amount) }));
  }

  res.json({ groups, total, page, pageSize, totalPages: Math.max(1, Math.ceil(total / pageSize)) });
}));

// Admin removes a member from a group.
app.delete('/api/admin/groups/:id/members/:userId', requireAdmin, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const userId = Number(req.params.userId);
  const [result] = await pool.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', [
    groupId,
    userId,
  ]);
  if (result.affectedRows === 0) return res.status(404).json({ error: 'That user is not in this group' });
  await logAdmin(req, 'remove_group_member', 'group', groupId, { userId });
  res.json({ ok: true });
}));

// Admin is the final decider on a group's withdrawal/support request.
app.post('/api/admin/groups/:groupId/requests/:reqId/respond', requireAdmin, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.groupId);
  const reqId = Number(req.params.reqId);
  const approve = !!req.body?.approve;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[request]] = await conn.query(
      "SELECT * FROM withdrawal_requests WHERE id = ? AND group_id = ? AND status = 'pending' FOR UPDATE",
      [reqId, groupId]
    );
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Request not found or already decided' });
    }
    const requestAmount = toCentavos(request.amount);

    if (approve) {
      const [[group]] = await conn.query('SELECT balance FROM `groups` WHERE id = ? FOR UPDATE', [groupId]);
      if (toCentavos(group.balance) < requestAmount) {
        await conn.rollback();
        return res.status(400).json({ error: 'Not enough funds in the group to approve this request' });
      }
      await conn.execute('UPDATE `groups` SET balance = balance - ? WHERE id = ?', [requestAmount, groupId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
        [
          'group',
          groupId,
          `Sent to ${request.requester_name} (Support)`,
          'Withdrawal',
          requestAmount,
          0,
          JSON.stringify({ reason: request.reason }),
        ]
      );
    }

    await conn.execute(
      'UPDATE withdrawal_requests SET status = ?, decided_by_admin_id = ?, decided_at = NOW() WHERE id = ?',
      [approve ? 'approved' : 'declined', req.adminId, reqId]
    );

    await conn.commit();
    await logAdmin(req, approve ? 'approve_group_withdrawal' : 'decline_group_withdrawal', 'withdrawal_request', reqId);
    res.json({ ok: true, status: approve ? 'approved' : 'declined' });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- admin transfer reversal ----------

// ---------- shared reversal core ----------
// Used by BOTH the admin reversal route and the user-facing /api/undo
// route, so there's one place that enforces the safety checks — no
// double-reversal, no letting a recipient's balance go negative.
async function reverseTransferByRef(conn, transferRef) {
  const [rows] = await conn.query(
    'SELECT id, account_type, account_id, label, type, amount, is_credit FROM transactions WHERE transfer_ref = ? FOR UPDATE',
    [transferRef]
  );

  if (rows.length === 0) {
    return { ok: false, status: 404, error: 'Transfer not found' };
  }

  const [[already]] = await conn.query('SELECT 1 FROM transactions WHERE reversed_transfer_ref = ?', [transferRef]);
  if (already) {
    return { ok: false, status: 409, error: 'This transfer has already been reversed' };
  }

  for (const row of rows) {
    if (row.account_type === 'user' && row.is_credit) {
      const [[recipientRow]] = await conn.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [row.account_id]);
      const amount = toCentavos(row.amount);
      if (toCentavos(recipientRow.balance) < amount) {
        return {
          ok: false,
          status: 409,
          error: 'Cannot reverse — the recipient no longer has sufficient balance to return the funds',
        };
      }
    }
  }

  const reversalTransferRef = crypto.randomUUID();
  const affectedUserIds = new Set();

  for (const row of rows) {
    const amount = toCentavos(row.amount);
    const reversalIsCredit = row.is_credit ? 0 : 1;
    const balanceDelta = row.is_credit ? -amount : amount;

    if (row.account_type === 'user') {
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [balanceDelta, row.account_id]);
      affectedUserIds.add(row.account_id);
    }

    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref, reversed_transfer_ref) VALUES (?,?,?,?,?,?,?,?)',
      [
        'user',
        row.account_id,
        `Reversal: ${row.label}`,
        row.type || 'Transfer Reversal',
        amount,
        reversalIsCredit,
        reversalTransferRef,
        transferRef,
      ]
    );
  }

  return { ok: true, reversalTransferRef, affectedUserIds };
}
app.get('/api/admin/transfers/:transferRef', requireAdmin, asyncRoute(async (req, res) => {
  const transferRef = req.params.transferRef;
  const [rows] = await pool.execute(
    `SELECT id, account_type AS accountType, account_id AS accountId, label, type, amount, is_credit AS isCredit, transfer_ref AS transferRef, created_at AS createdAt
     FROM transactions
     WHERE transfer_ref = ?
     ORDER BY created_at ASC`,
    [transferRef]
  );

  if (rows.length === 0) {
    return res.status(404).json({ error: 'Transfer not found' });
  }

  res.json({ transferRef, entries: rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })) });
}));

app.post('/api/admin/transfers/:transferRef/reverse', requireAdmin, asyncRoute(async (req, res) => {
  const transferRef = req.params.transferRef;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await reverseTransferByRef(conn, transferRef);
    if (!result.ok) {
      await conn.rollback();
      return res.status(result.status).json({ error: result.error });
    }
    await conn.commit();
    await Promise.all([...result.affectedUserIds].map(refreshUserInIndex));
    await logAdmin(req, 'reverse_transfer', 'transfer', transferRef, { reversalTransferRef: result.reversalTransferRef });
    res.json({ ok: true, transferRef, reversalTransferRef: result.reversalTransferRef });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));
const UNDO_WINDOW_MS = 60 * 1000;

app.post('/api/undo', requireAuth, moneyLimiter, asyncRoute(async (req, res) => {
  const stack = getUndoStack(req.userId);
  if (stack.isEmpty()) {
    return res.status(400).json({ error: 'Nothing to undo' });
  }

  const entry = stack.pop(); // LIFO — most recent transfer undone first
  // Undo is only for "oops" moments. After the window closes the money can only
  // be reversed by an admin, so a payment can't be taken back later.
  if (Date.now() - entry.at > UNDO_WINDOW_MS) {
    while (!stack.isEmpty()) stack.pop(); // everything older is expired too
    return res.status(400).json({ error: 'Undo is only available for 60 seconds after a payment' });
  }
  const transferRef = entry.ref;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await reverseTransferByRef(conn, transferRef);
    if (!result.ok) {
      await conn.rollback();
      stack.push(entry); // undo failed — put it back so the user can see why / retry later
      return res.status(result.status).json({ error: result.error });
    }
    await conn.commit();
    await Promise.all([...result.affectedUserIds].map(refreshUserInIndex));
    res.json({ ok: true, undone: transferRef, reversalTransferRef: result.reversalTransferRef });
  } catch (err) {
    await conn.rollback();
    stack.push(entry);
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- loans (multi-admin verified, like a real loan) ----------
//
// Applying for a loan does NOT touch the user's balance. It creates a
// `pending` row. Each admin can cast exactly one decision on it (enforced
// by the loan_approvals UNIQUE(loan_id, admin_id) constraint, not just a
// UI check). Once the loan's approvals_needed distinct admins have
// approved, it flips to `approved` and the principal is disbursed in the
// same transaction. A single decline closes the loan immediately, no
// further voting possible.
//
// What makes this closer to a real loan instead of "ask for money":
//
// 1. LEGAL / ELIGIBILITY GATE — mirrors what an actual lender checks before
//    accepting an application at all:
//      - applicant must self-declare as 18+ (MIN_AGE)
//      - a government-issued ID number must be provided
//      - the applicant must explicitly acknowledge the loan terms
//      - the account must be at least MIN_ACCOUNT_AGE_DAYS old
//      - no other loan already pending/approved (one active loan at a time)
//      - first-time borrowers are capped at MAX_FIRST_LOAN_AMOUNT_CENTAVOS —
//        real lenders don't require you to already have money in the bank
//        to get a loan, so this is NOT tied to current balance.
//
// 2. TIERED APPROVAL — bigger asks need more sign-offs, i.e. it escalates
//    to more "higher-ups" the larger the loan, via approvalsNeededFor().
//    The number of approvals a given loan needs is decided ONCE at
//    application time and stored on the row (loans.approvals_needed), so
//    it can't drift if the tier thresholds change later.

const MIN_ACCOUNT_AGE_DAYS = 3;
const MIN_AGE = 18;
const MAX_FIRST_LOAN_AMOUNT_CENTAVOS = 1_000_000; // ₱10,000.00
const LOAN_TIER_1_CENTAVOS = 500_000; // ₱5,000.00
const LOAN_TIER_2_CENTAVOS = 2_000_000; // ₱20,000.00

function approvalsNeededFor(amountCentavos) {
  if (amountCentavos <= LOAN_TIER_1_CENTAVOS) return 1;
  if (amountCentavos <= LOAN_TIER_2_CENTAVOS) return 2;
  return 3;
}

app.post('/api/loans', requireAuth, asyncRoute(async (req, res) => {
  const { loanType, amountCentavos, purpose, termMonths, age, governmentId, legalAck } = req.body || {};
  const amt = parseCentavos(amountCentavos);
  const term = Number(termMonths);
  const applicantAge = Number(age);

  if (!loanType || !loanType.toString().trim()) return res.status(400).json({ error: 'A loan platform/type is required' });
  if (amt === null) return res.status(400).json({ error: 'A positive loan amount (integer centavos) is required' });
  if (!purpose || !purpose.toString().trim()) return res.status(400).json({ error: 'A purpose is required' });
  if (!Number.isInteger(term) || term <= 0) return res.status(400).json({ error: 'A valid term (in months) is required' });
  if (!Number.isInteger(applicantAge) || applicantAge <= 0) return res.status(400).json({ error: 'A valid age is required' });
  if (applicantAge < MIN_AGE) return res.status(400).json({ error: `You must be at least ${MIN_AGE} years old to apply for a loan` });
  if (!governmentId || !governmentId.toString().trim()) return res.status(400).json({ error: 'A government-issued ID number is required' });
  if (!legalAck) return res.status(400).json({ error: 'You must acknowledge the loan terms and conditions to proceed' });
  if (amt > MAX_FIRST_LOAN_AMOUNT_CENTAVOS) {
    return res.status(400).json({
      error: `First-time borrowers are capped at ₱${centavosToPesosLabel(MAX_FIRST_LOAN_AMOUNT_CENTAVOS)} — try a smaller amount`,
    });
  }

  const [[user]] = await pool.query('SELECT created_at FROM users WHERE id = ?', [req.userId]);

  const accountAgeDays = (Date.now() - new Date(user.created_at).getTime()) / (1000 * 60 * 60 * 24);
  if (accountAgeDays < MIN_ACCOUNT_AGE_DAYS) {
    return res.status(400).json({
      error: `Your account needs to be at least ${MIN_ACCOUNT_AGE_DAYS} day(s) old before you're eligible for a loan`,
    });
  }

  const [[{ activeCount }]] = await pool.query(
    "SELECT COUNT(*) AS activeCount FROM loans WHERE user_id = ? AND status IN ('pending','approved')",
    [req.userId]
  );
  if (activeCount > 0) {
    return res.status(400).json({ error: 'You already have a pending or active loan — repay or resolve it before applying again' });
  }

 const approvalsNeeded = approvalsNeededFor(amt);
  const [result] = await pool.execute(
    `INSERT INTO loans (user_id, loan_type, amount, purpose, term_months, applicant_age, government_id, legal_ack, approvals_needed)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    [
      req.userId,
      cleanText(loanType, 50),
      amt,
      cleanText(purpose, 255),
      term,
      applicantAge,
      governmentId.toString().trim(),
      legalAck ? 1 : 0,
      approvalsNeeded,
    ]
  );

  loanQueue.enqueue({ loanId: result.insertId, userId: req.userId }); // NEW — item: mandatory "Queue"

  res.json({ id: result.insertId, ok: true, approvalsNeeded });
}));

app.get('/api/loans/mine', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.applicant_age AS applicantAge, l.government_id AS governmentId,
            l.amount_repaid AS amountRepaid, l.created_at, l.approvals_needed AS approvalsNeeded,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount
     FROM loans l WHERE l.user_id = ? ORDER BY l.created_at DESC`,
    [req.userId]
  );
  res.json(rows.map((l) => ({ ...l, amount: toCentavos(l.amount), amountRepaid: toCentavos(l.amountRepaid) })));
}));

app.post('/api/loans/:id/repay', requireAuth, asyncRoute(async (req, res) => {
  const loanId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive repayment amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[loan]] = await conn.query('SELECT * FROM loans WHERE id = ? AND user_id = ? FOR UPDATE', [
      loanId,
      req.userId,
    ]);
    if (!loan) {
      await conn.rollback();
      return res.status(404).json({ error: 'Loan not found' });
    }
    if (loan.status !== 'approved') {
      await conn.rollback();
      return res.status(400).json({ error: 'This loan is not active' });
    }

    const [[user]] = await conn.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    if (toCentavos(user.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const loanAmount = toCentavos(loan.amount);
    const loanRepaid = toCentavos(loan.amount_repaid);
    const remaining = loanAmount - loanRepaid;
    const applied = Math.min(amt, remaining);
    const newRepaid = loanRepaid + applied;
    const nowRepaid = newRepaid >= loanAmount;

    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [applied, req.userId]);
    await conn.execute('UPDATE loans SET amount_repaid = ?, status = ? WHERE id = ?', [
      newRepaid,
      nowRepaid ? 'repaid' : 'approved',
      loanId,
    ]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Loan Repayment (Loan #${loanId})`, 'Loan Repayment', applied, 0]
    );

    await conn.commit();

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json({ ok: true, remaining: loanAmount - newRepaid });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// Admin oversight: every loan with how many approvals it has and needs, and
// whether THIS admin has already decided on it (so the UI can hide the
// buttons instead of letting them try to vote twice and get a 409).
app.get('/api/admin/loans', requireAdmin, asyncRoute(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize) || 50));
  const offset = (page - 1) * pageSize;
  const search = req.query.search ? `%${req.query.search.toString().trim()}%` : null;
  const status = ['pending', 'approved', 'declined', 'repaid'].includes(req.query.status) ? req.query.status : null;

  const conditions = [];
  const params = [];
  if (search) { conditions.push('u.username LIKE ?'); params.push(search); }
  if (status) { conditions.push('l.status = ?'); params.push(status); }
  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const [[{ total }]] = await pool.query(
    `SELECT COUNT(*) AS total FROM loans l JOIN users u ON u.id = l.user_id ${whereClause}`,
    params
  );

  const [rows] = await pool.query(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.applicant_age AS applicantAge, l.government_id AS governmentId,
            l.amount_repaid AS amountRepaid, l.created_at, l.approvals_needed AS approvalsNeeded, u.username,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount,
            EXISTS(SELECT 1 FROM loan_approvals la WHERE la.loan_id = l.id AND la.admin_id = ?) AS decidedByMe,
            EXISTS(SELECT 1 FROM loan_approvals la WHERE la.loan_id = l.id AND la.admin_id = ? AND la.decision = 'approve') AS approvedByMe
     FROM loans l JOIN users u ON u.id = l.user_id
     ${whereClause}
     ORDER BY (l.status = 'pending') DESC, l.created_at DESC
     LIMIT ? OFFSET ?`,
    [req.adminId, req.adminId, ...params, pageSize, offset]
  );

  const loans = rows.map((l) => ({ ...l, amount: toCentavos(l.amount), amountRepaid: toCentavos(l.amountRepaid) }));

  res.json({ loans, total, page, pageSize, totalPages: Math.max(1, Math.ceil(total / pageSize)) });
}));

app.post('/api/admin/loans/:id/respond', requireAdmin, asyncRoute(async (req, res) => {
  const loanId = Number(req.params.id);
  const approve = !!req.body?.approve;

  // Oldest-first is enforced as a *display* priority (see GET /api/admin/loans'
  // ORDER BY and /api/admin/loans/queue/next), not as a hard gate here —
  // with more than one admin online, forcing everyone through a single
  // front-of-queue loan serializes all approval work through one door
  // regardless of admin count. The actual safety against two admins
  // colliding on the *same* loan comes from the row lock + already-voted
  // check just below, not from queue order.

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[loan]] = await conn.query("SELECT * FROM loans WHERE id = ? AND status = 'pending' FOR UPDATE", [
      loanId,
    ]);
    if (!loan) {
      await conn.rollback();
      return res.status(404).json({ error: 'Loan not found or already decided' });
    }

    const [[already]] = await conn.query('SELECT 1 FROM loan_approvals WHERE loan_id = ? AND admin_id = ?', [
      loanId,
      req.adminId,
    ]);
    if (already) {
      await conn.rollback();
      return res.status(409).json({ error: 'You already voted on this loan' });
    }

    await conn.execute('INSERT INTO loan_approvals (loan_id, admin_id, decision) VALUES (?,?,?)', [
      loanId,
      req.adminId,
      approve ? 'approve' : 'decline',
    ]);

    if (!approve) {
      await conn.execute("UPDATE loans SET status = 'declined', decided_at = NOW() WHERE id = ?", [loanId]);
      await conn.commit();
      loanQueue.remove(loanId); // finalized — remove wherever it sits in the queue, not just the front
      await logAdmin(req, 'decline_loan', 'loan', loanId);
      return res.json({ ok: true, status: 'declined' });
    }

    const [[{ approvals }]] = await conn.query(
      "SELECT COUNT(*) AS approvals FROM loan_approvals WHERE loan_id = ? AND decision = 'approve'",
      [loanId]
    );

    if (approvals >= loan.approvals_needed) {
      const loanAmount = toCentavos(loan.amount);
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [loanAmount, loan.user_id]);
      await conn.execute("UPDATE loans SET status = 'approved', decided_at = NOW() WHERE id = ?", [loanId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
        [
          'user',
          loan.user_id,
          `Loan Disbursed (${loan.term_months}-month term)`,
          'Loan Disbursement',
          loanAmount,
          1,
          JSON.stringify({ purpose: loan.purpose }),
        ]
      );
      await conn.commit();

      await refreshUserInIndex(loan.user_id);
      loanQueue.remove(loanId); // finalized — remove wherever it sits in the queue, not just the front

      await logAdmin(req, 'approve_loan', 'loan', loanId, { amount: loan.amount });
      return res.json({ ok: true, status: 'approved' });
    }

    // Still needs more admin approvals — stays in the queue, since it's
    // not finalized yet.
    await conn.commit();
    await logAdmin(req, 'vote_approve_loan', 'loan', loanId, { approvals });
    res.json({ ok: true, status: 'pending', approvalsCount: approvals, approvalsNeeded: loan.approvals_needed });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.get('/api/admin/loans/queue/next', requireAdmin, asyncRoute(async (req, res) => {
  const front = loanQueue.peek();
  if (!front) {
    return res.json({ empty: true });
  }

  const [[loan]] = await pool.query(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.approvals_needed AS approvalsNeeded, u.username,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount
     FROM loans l JOIN users u ON u.id = l.user_id
     WHERE l.id = ?`,
    [front.loanId]
  );

  res.json({ empty: false, loan: { ...loan, amount: toCentavos(loan.amount) } });
}));

app.get('/api/admin/accounts/traverse', requireAdmin, (req, res) => {
  const direction = req.query.direction === 'backward' ? 'backward' : 'forward';
  const rows = direction === 'backward' ? accountList.traverseBackward() : accountList.traverseForward();
  res.json({
    direction,
    count: rows.length,
    accounts: rows.map((u) => ({
      id: u.id,
      username: u.username,
      walletId: u.wallet_id,
      balance: toCentavos(u.balance),
    })),
  });
});

app.get('/api/admin/accounts/avl-search/:walletId', requireAdmin, (req, res) => {
  const walletId = req.params.walletId;
  const account = walletAvl.search(walletId);

  if (!account) {
    return res.status(404).json({ error: 'No account found for that Wallet ID' });
  }

  res.json({
    foundVia: 'AVL tree search',
    treeHeight: walletAvl.height(),
    treeSize: walletAvl.size,
    account: {
      id: account.id,
      username: account.username,
      walletId: account.wallet_id,
      balance: toCentavos(account.balance),
    },
  });
});

// ---------- provider network simulation (item #4 redesign) ----------
//
// This is a SIMULATION only — no real bank/provider API is called. It
// finds the lowest-fee simulated path across a small, static provider
// graph (see graph.js). Every response is explicitly marked
// `simulated: true` so it's never mistaken for a live routing quote.

app.get('/api/routes/providers', requireAuth, (req, res) => {
  res.json(PROVIDERS);
});

app.get('/api/routes/compare', requireAuth, (req, res) => {
  const { source, destination } = req.query;
  if (!source || !destination) {
    return res.status(400).json({ error: 'source and destination provider ids are required' });
  }

  const result = findCheapestRoute(source, destination);
  if (!result) {
    return res.status(404).json({ error: 'No simulated route found between those providers' });
  }

  res.json({ simulated: true, source, destination, ...result });
});

// ---------- admin: identity verification review ----------

app.get('/api/admin/verifications/pending', requireAdmin, asyncRoute(async (req, res) => {
  const [rows] = await pool.query(
    `SELECT id, username, phone_number AS phoneNumber, government_id_number AS governmentIdNumber,
            government_id_photo AS governmentIdPhotoFront, government_id_photo_back AS governmentIdPhotoBack,
            selfie_photo AS selfiePhoto, face_match_confidence AS faceMatchConfidence, created_at AS createdAt
     FROM users
     WHERE verification_status = 'pending'
     ORDER BY created_at ASC`
  );
  res.json(
    rows.map((r) => ({
      ...r,
      governmentIdPhotoFront: decryptPhoto(r.governmentIdPhotoFront),
      governmentIdPhotoBack: decryptPhoto(r.governmentIdPhotoBack),
      selfiePhoto: decryptPhoto(r.selfiePhoto),
    }))
  );
}));

app.post('/api/admin/verifications/:id/respond', requireAdmin, asyncRoute(async (req, res) => {
  const userId = Number(req.params.id);
  const approve = !!req.body?.approve;
  if (!Number.isInteger(userId)) return res.status(400).json({ error: 'Invalid user ID' });

  const [[user]] = await pool.query(
    "SELECT id, verification_status FROM users WHERE id = ?",
    [userId]
  );
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.verification_status !== 'pending') {
    return res.status(409).json({ error: 'This account has already been decided' });
  }

  await pool.execute('UPDATE users SET verification_status = ? WHERE id = ?', [
    approve ? 'approved' : 'rejected',
    userId,
  ]);
  // The photos were only needed for this review. Delete them once decided.
  if (!KEEP_ID_PHOTOS) {
    await pool.execute(
      "UPDATE users SET government_id_photo = '', government_id_photo_back = '', selfie_photo = '' WHERE id = ?",
      [userId]
    );
  }

  await refreshUserInIndex(userId);
  await logAdmin(req, approve ? 'approve_verification' : 'reject_verification', 'user', userId);
  res.json({ ok: true, status: approve ? 'approved' : 'rejected' });
}));

// This must be registered AFTER every route above it — Express matches
// error-handling middleware (4-arg signature) only for errors that occur
// during/after routes already registered before it in the file.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------- WebSocket server: live balance updates ----------
// Wrapping the Express app in a plain http.Server lets the same port
// serve both the REST API and the WebSocket upgrade at /ws — no second
// port/process to deploy or configure.
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 4096 });

// The session token is NOT taken from the URL (web addresses end up in proxy
// and server logs). The client connects, then must send
//   {"type":"auth","token":"<jwt>"}
// as its first message within 5 seconds, or it is disconnected. The token is
// checked with the same rules as requireAuth: full stage, user role.
wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => {
    ws.isAlive = true;
  });
  const authTimer = setTimeout(() => ws.close(4001, 'Not authenticated'), 5000);
  ws.on('close', () => clearTimeout(authTimer));
  ws.on('error', () => clearTimeout(authTimer));

  ws.once('message', (data) => {
    clearTimeout(authTimer);
    let userId;
    try {
      const msg = JSON.parse(data.toString());
      const payload = msg && msg.type === 'auth' ? verify(msg.token) : null;
      if (!payload || payload.stage !== 'full' || payload.role !== 'user') {
        ws.close(4001, 'Not authenticated');
        return;
      }
      userId = payload.uid;
    } catch {
      ws.close(4001, 'Not authenticated');
      return;
    }

    registerSocket(userId, ws);
    ws.on('close', () => unregisterSocket(userId, ws));
    ws.on('error', () => unregisterSocket(userId, ws));

    // Send the current balance immediately, so the client has a correct
    // number even if it connects between polls/actions.
    pool
      .query('SELECT balance FROM users WHERE id = ?', [userId])
      .then(([[row]]) => {
        if (row) pushToUser(userId, { type: 'balance', balanceCentavos: toCentavos(row.balance) });
      })
      .catch(() => {});
  });
});

// Phones and flaky networks often drop a WebSocket without a clean close
// frame. Ping every 30s and terminate anything that didn't pong back
// since the last check, so userSockets doesn't accumulate dead entries.
const wsHeartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);
wss.on('close', () => clearInterval(wsHeartbeat));

const port = process.env.PORT || 3000;
(async () => {
  // First deploy on a new, empty database: set AUTO_SETUP_DB=true once and the
  // tables are created before anything tries to read them.
  if (process.env.AUTO_SETUP_DB === 'true') {
    await require('./setup-db').setupDatabase();
  }
  await Promise.all([
    loadIndexesFromDatabase(),
    loadLoanQueueFromDatabase(),
    loadAccountListFromDatabase(),
    loadWalletAvlFromDatabase(),
  ]);
  server.listen(port, () => console.log(`PayCST backend listening on port ${port} (HTTP + WebSocket /ws)`));
})().catch((err) => {
  console.error('Startup failed:', err.message);
  process.exit(1);
});

// ---------- provider network simulation and DB migration notes below are unchanged ----------