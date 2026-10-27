const path = require('path');
const express = require('express');
const chalk = require('chalk');
const { run, get, all } = require('../database/db');
const { requireVulnerableLogin } = require('../middleware/auth');

const router = express.Router();
const viewsPath = path.join(__dirname, '..', 'views', 'vulnerable');

router.get('/login', (req, res) => res.sendFile(path.join(viewsPath, 'login.html')));
router.get('/register', (req, res) => res.sendFile(path.join(viewsPath, 'register.html')));
router.get('/dashboard', requireVulnerableLogin, (req, res) =>
  res.sendFile(path.join(viewsPath, 'dashboard.html'))
);

router.post('/register', async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    // VULNERABLE: plain-text password storage. Anyone who steals the DB gets usable passwords.
    const sql = `INSERT INTO vulnerable_users (username, email, password) VALUES ('${username}', '${email}', '${password}')`;
    await run(sql);

    console.log(chalk.yellow(`[vulnerable-register] Stored plain password for ${username}`));
    res.redirect('/vulnerable/login?registered=1');
  } catch (err) {
    res.status(400).send('Registration failed. Try another username.');
  }
});

router.post('/login', async (req, res, next) => {
  const { username, password } = req.body;

  try {
    // VULNERABLE: direct string interpolation allows SQL Injection.
    // Try ' OR '1'='1 in both fields to bypass authentication.
    const sql = `SELECT * FROM vulnerable_users WHERE username = '${username}' AND password = '${password}'`;
    const user = await get(sql);

    await run(
      'INSERT INTO login_attempts (lab_type, username, ip_address, success) VALUES (?, ?, ?, ?)',
      ['vulnerable', username || 'unknown', req.ip, user ? 1 : 0]
    );

    console.log(
      user
        ? chalk.red(`[vulnerable-login] Login accepted for input: ${username}`)
        : chalk.yellow(`[vulnerable-login] Failed login for input: ${username}`)
    );

    if (!user) {
      return res.redirect('/vulnerable/login?error=1');
    }

    // VULNERABLE: session is not regenerated after login and stores more data than needed.
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      password: user.password,
      role: user.role
    };
    res.redirect('/vulnerable/dashboard');
  } catch (err) {
    next(err);
  }
});

router.post('/comments', requireVulnerableLogin, async (req, res, next) => {
  try {
    const { message } = req.body;
    const username = req.session.user.username;

    // VULNERABLE: unsanitized content is stored and later rendered with innerHTML.
    // Try: <script>alert("XSS")</script>
    const sql = `INSERT INTO vulnerable_comments (user_id, username, message) VALUES (${req.session.user.id}, '${username}', '${message}')`;
    await run(sql);
    res.redirect('/vulnerable/dashboard');
  } catch (err) {
    next(err);
  }
});

router.get('/api/dashboard', requireVulnerableLogin, async (req, res, next) => {
  try {
    const comments = await all('SELECT * FROM vulnerable_comments ORDER BY created_at DESC LIMIT 25');
    const attempts = await all(
      'SELECT * FROM login_attempts WHERE lab_type = ? ORDER BY created_at DESC LIMIT 10',
      ['vulnerable']
    );
    res.json({ user: req.session.user, comments, attempts });
  } catch (err) {
    next(err);
  }
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/vulnerable/login'));
});

module.exports = router;
