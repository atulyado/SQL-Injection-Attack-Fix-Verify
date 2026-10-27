const bcrypt = require('bcryptjs');
const { run, get } = require('./db');

async function ensureDatabase() {
  await run(`
    CREATE TABLE IF NOT EXISTS vulnerable_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'student',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS secure_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'student',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS vulnerable_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS secure_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      lab_type TEXT NOT NULL,
      username TEXT NOT NULL,
      ip_address TEXT,
      success INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const vulnerableAdmin = await get('SELECT id FROM vulnerable_users WHERE username = ?', ['admin']);
  if (!vulnerableAdmin) {
    // Intentionally weak: this password is stored in plain text for the vulnerable demo.
    await run(
      'INSERT INTO vulnerable_users (username, email, password, role) VALUES (?, ?, ?, ?)',
      ['admin', 'admin@lab.local', 'admin123', 'admin']
    );
  }

  const secureAdmin = await get('SELECT id FROM secure_users WHERE username = ?', ['admin']);
  if (!secureAdmin) {
    const hash = await bcrypt.hash('Admin123!', 12);
    await run(
      'INSERT INTO secure_users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      ['admin', 'admin-secure@lab.local', hash, 'admin']
    );
  }
}

if (require.main === module) {
  ensureDatabase()
    .then(() => {
      console.log('Database initialized.');
      process.exit(0);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}

module.exports = { ensureDatabase };
