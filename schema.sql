-- PayCST backend: COMPLETE, CURRENT database schema (for a brand-new database).
-- Built from what server.js actually reads and writes. The old schema.sql in
-- the repo was missing the phone / ID / photo / verification columns and the
-- savings, group-request and login-attempt tables.
--
-- Money is stored as whole centavos (BIGINT), never decimals.
--
-- On Railway / most hosts the database already exists, so skip the first two
-- lines (CREATE DATABASE / USE) and select your database in your SQL tool.

CREATE DATABASE IF NOT EXISTS paycst CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE paycst;

-- ---------- admins ----------
CREATE TABLE IF NOT EXISTS admins (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  password_hash CHAR(60) NOT NULL,
  pin_hash CHAR(60) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_admin_username (username)
) ENGINE=InnoDB;

-- ---------- users ----------
-- UNIQUE keys on username, wallet_id (= phone number), phone_number and
-- government_id_number make the DATABASE refuse duplicate accounts even if two
-- sign-ups arrive at the same instant.
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  password_hash CHAR(60) NOT NULL,
  pin_hash CHAR(60) NOT NULL,
  wallet_id VARCHAR(20) NOT NULL,
  balance BIGINT NOT NULL DEFAULT 0,
  phone_number VARCHAR(20) NULL,
  government_id_number VARCHAR(64) NULL,
  government_id_photo LONGTEXT NULL,
  government_id_photo_back LONGTEXT NULL,
  selfie_photo LONGTEXT NULL,
  terms_accepted_at TIMESTAMP NULL,
  verification_status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  face_match_confidence DOUBLE NULL,
  status ENUM('active','suspended') NOT NULL DEFAULT 'active',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_users_username (username),
  UNIQUE KEY uniq_users_wallet (wallet_id),
  UNIQUE KEY uniq_users_phone (phone_number),
  UNIQUE KEY uniq_users_gov_id (government_id_number),
  KEY idx_users_verification (verification_status)
) ENGINE=InnoDB;

-- ---------- groups ----------
CREATE TABLE IF NOT EXISTS `groups` (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  balance BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS group_members (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  user_id INT NOT NULL,
  joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_member (group_id, user_id),
  KEY idx_member_user (user_id),
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS group_join_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  user_id INT NOT NULL,
  status ENUM('pending','approved','declined') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_join_group (group_id, status),
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS group_withdraw_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  requester_id INT NOT NULL,
  amount BIGINT NOT NULL,
  reason VARCHAR(255) NOT NULL,
  approvals_needed INT NOT NULL DEFAULT 1,
  status ENUM('pending','approved','declined') NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_gwr_group (group_id, status),
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS group_withdraw_approvals (
  id INT AUTO_INCREMENT PRIMARY KEY,
  request_id INT NOT NULL,
  member_id INT NOT NULL,
  decision ENUM('approve','decline') NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_member_request (request_id, member_id),
  FOREIGN KEY (request_id) REFERENCES group_withdraw_requests(id) ON DELETE CASCADE,
  FOREIGN KEY (member_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Older admin-approved group withdrawal flow (still referenced by the code).
CREATE TABLE IF NOT EXISTS withdrawal_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  requester_name VARCHAR(100) NOT NULL,
  reason VARCHAR(255) NOT NULL,
  amount BIGINT NOT NULL,
  status ENUM('pending','approved','declined') NOT NULL DEFAULT 'pending',
  decided_by_admin_id INT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at TIMESTAMP NULL,
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (decided_by_admin_id) REFERENCES admins(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ---------- money ----------
CREATE TABLE IF NOT EXISTS transactions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  account_type ENUM('user','group') NOT NULL,
  account_id INT NOT NULL,
  label VARCHAR(200) NOT NULL,
  type VARCHAR(50) NOT NULL,
  amount BIGINT NOT NULL,
  is_credit TINYINT(1) NOT NULL,
  transfer_ref VARCHAR(64) NULL,
  details JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_tx_account (account_type, account_id, created_at),
  KEY idx_tx_ref (transfer_ref)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS savings_goals (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  target_amount BIGINT NOT NULL,
  saved_amount BIGINT NOT NULL DEFAULT 0,
  status ENUM('active','completed') NOT NULL DEFAULT 'active',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_savings_user (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------- loans ----------
CREATE TABLE IF NOT EXISTS loans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  loan_type VARCHAR(50) NOT NULL DEFAULT 'Personal Loan',
  amount BIGINT NOT NULL,
  purpose VARCHAR(255) NOT NULL,
  term_months INT NOT NULL,
  applicant_age INT NOT NULL DEFAULT 18,
  government_id VARCHAR(50) NOT NULL DEFAULT '',
  legal_ack TINYINT(1) NOT NULL DEFAULT 0,
  status ENUM('pending','approved','declined','repaid') NOT NULL DEFAULT 'pending',
  amount_repaid BIGINT NOT NULL DEFAULT 0,
  approvals_needed INT NOT NULL DEFAULT 2,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at TIMESTAMP NULL DEFAULT NULL,
  KEY idx_loans_user (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS loan_approvals (
  id INT AUTO_INCREMENT PRIMARY KEY,
  loan_id INT NOT NULL,
  admin_id INT NOT NULL,
  decision ENUM('approve','decline') NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_admin_loan (loan_id, admin_id),
  FOREIGN KEY (loan_id) REFERENCES loans(id) ON DELETE CASCADE,
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------- admin audit log (who did what) ----------
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  admin_id INT NULL,
  action VARCHAR(50) NOT NULL,
  target_type VARCHAR(30) NOT NULL,
  target_id VARCHAR(64) NOT NULL,
  details JSON NULL,
  ip VARCHAR(64) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_audit_admin (admin_id, created_at),
  KEY idx_audit_target (target_type, target_id)
) ENGINE=InnoDB;

-- ---------- fingerprint / device login tokens ----------
CREATE TABLE IF NOT EXISTS device_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token_hash CHAR(64) NOT NULL,
  device_name VARCHAR(100) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TIMESTAMP NULL,
  expires_at TIMESTAMP NOT NULL,
  UNIQUE KEY uniq_device_token (token_hash),
  KEY idx_device_user (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------- login lockouts (survive server restarts) ----------
CREATE TABLE IF NOT EXISTS login_attempts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  identifier VARCHAR(100) NOT NULL,
  attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_attempts (identifier, attempted_at)
) ENGINE=InnoDB;

-- ---------- phone verification codes (sign-up SMS) ----------
CREATE TABLE IF NOT EXISTS phone_otps (
  id INT AUTO_INCREMENT PRIMARY KEY,
  phone_number VARCHAR(20) NOT NULL,
  code_hash CHAR(64) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  expires_at DATETIME NOT NULL,
  consumed TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_phone_otps (phone_number, created_at)
) ENGINE=InnoDB;

-- No admin is created here on purpose. After loading this schema run:
--   node create-admin.js <username> <password> <4-digit-pin>