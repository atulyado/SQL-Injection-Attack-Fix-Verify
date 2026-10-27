const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const chalk = require('chalk');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const { run, get, all } = require('../database/db');
const { requireSecureLogin } = require('../middleware/auth');

const router = express.Router();
const viewsPath = path.join(__dirname, '..', 'views', 'secure');

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Please wait 10 minutes and try again.'
});

function cleanMessage(input) {
  return validator.escape(String(input || '').trim()).slice(0, 500);
}

router.get('/login', (req, res) => res.sendFile(path.join(viewsPath, 'login.html')));
router.get('/register', (req, res) => res.sendFile(path.join(viewsPath, 'register.html')));
router.get('/dashboard', requireSecureLogin, (req, res) =>
  res.sendFile(path.join(viewsPath, 'dashboard.html'))
);

router.post('/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!validator.isAlphanumeric(username) || username.length < 3 || username.length > 24) {
      return res.status(400).send('Username must be 3-24 letters or numbers.');
    }
    if (!validator.isEmail(email)) {
      return res.status(400).send('Please use a valid email address.');
    }
    if (!validator.isStrongPassword(password, { minLength: 8, minSymbols: 1 })) {
      return res.status(400).send('Password must be at least 8 characters with a symbol.');
    }

    // SECURE: passwords are never stored directly. bcrypt stores a salted one-way hash.
    const passwordHash = await bcrypt.hash(password, 12);

    // SECURE: placeholders keep user input separate from SQL instructions.
    await run(
      'INSERT INTO secure_users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, passwordHash]
    );

    console.log(chalk.blue(`[secure-register] Created hashed-password account for ${username}`));
    res.redirect('/secure/login?registered=1');
  } catch (err) {
    res.status(400).send('Registration failed. The username or email may already exist.');
  }
});

router.post('/login', loginLimiter, async (req, res, next) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');

  try {
    // SECURE: parameterized query prevents SQL Injection payloads from changing query logic.
    const user = await get('SELECT * FROM secure_users WHERE username = ?', [username]);
    const isValid = user ? await bcrypt.compare(password, user.password_hash) : false;

    await run(
      'INSERT INTO login_attempts (lab_type, username, ip_address, success) VALUES (?, ?, ?, ?)',
      ['secure', username || 'unknown', req.ip, isValid ? 1 : 0]
    );

    console.log(
      isValid
        ? chalk.green(`[secure-login] Login accepted for ${username}`)
        : chalk.yellow(`[secure-login] Failed login for ${username}`)
    );

    if (!isValid) {
      return res.redirect('/secure/login?error=1');
    }

    // SECURE: regenerate the session ID after login to reduce session fixation risk.
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.createdAt = Date.now();
      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      };
      res.redirect('/secure/dashboard');
    });
  } catch (err) {
    next(err);
  }
});

router.post('/comments', requireSecureLogin, async (req, res, next) => {
  try {
    // SECURE: encode dangerous characters before storing and render with textContent in the UI.
    const message = cleanMessage(req.body.message);
    if (!message) {
      return res.status(400).send('Message cannot be empty.');
    }

    await run(
      'INSERT INTO secure_comments (user_id, username, message) VALUES (?, ?, ?)',
      [req.session.user.id, req.session.user.username, message]
    );
    res.redirect('/secure/dashboard');
  } catch (err) {
    next(err);
  }
});

router.get('/api/dashboard', requireSecureLogin, async (req, res, next) => {
  try {
    const comments = await all('SELECT * FROM secure_comments ORDER BY created_at DESC LIMIT 25');
    const attempts = await all(
      'SELECT * FROM login_attempts WHERE lab_type = ? ORDER BY created_at DESC LIMIT 10',
      ['secure']
    );
    res.json({ user: req.session.user, comments, attempts });
  } catch (err) {
    next(err);
  }
});

router.post('/logout', requireSecureLogin, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('secure_lab_sid');
    res.redirect('/secure/login');
  });
});

module.exports = router;
