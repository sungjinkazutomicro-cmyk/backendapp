// Creates every table the backend needs (safe to run again: it only creates
// what is missing). The server runs this by itself on startup when the
// variable AUTO_SETUP_DB=true is set, or you can run it by hand: npm run setup-db
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

async function setupDatabase() {
  let sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  // Hosted databases already exist, so drop the CREATE DATABASE / USE lines.
  sql = sql
    .replace(/^\s*CREATE DATABASE[^;]*;\s*$/gim, '')
    .replace(/^\s*USE\s+[^;]*;\s*$/gim, '');

  const conn = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    multipleStatements: true,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: true } : undefined,
  });
  try {
    await conn.query(sql);

    // CREATE TABLE IF NOT EXISTS never changes a table that already exists, so
    // columns added later have to be added here for databases made earlier.
    const missingColumns = [
      {
        table: 'transactions',
        column: 'reversed_transfer_ref',
        add: 'ADD COLUMN reversed_transfer_ref VARCHAR(64) NULL, ADD KEY idx_tx_reversed (reversed_transfer_ref)',
      },
    ];
    for (const { table, column, add } of missingColumns) {
      const [found] = await conn.query(
        'SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?',
        [table, column]
      );
      if (found.length === 0) {
        await conn.query(`ALTER TABLE \`${table}\` ${add}`);
        console.log(`Added missing column ${table}.${column}`);
      }
    }

    console.log('Database tables are ready.');
  } finally {
    await conn.end();
  }
}

module.exports = { setupDatabase };

if (require.main === module) {
  setupDatabase()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Database setup failed:', err.message);
      process.exit(1);
    });
}