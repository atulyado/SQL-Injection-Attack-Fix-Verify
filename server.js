const path = require('path');
const express = require('express');
const session = require('express-session');
const morgan = require('morgan');
const chalk = require('chalk');
const helmet = require('helmet');

const vulnerableRoutes = require('./routes/vulnerableRoutes');
const secureRoutes = require('./routes/secureRoutes');
const { ensureDatabase } = require('./database/init');
const SqliteSessionStore = require('./database/sessionStore');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = '127.0.0.1';

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  morgan((tokens, req, res) => {
    const status = Number(tokens.status(req, res));
    const color = status >= 500 ? chalk.red : status >= 400 ? chalk.yellow : chalk.green;
    return [
      chalk.cyan(tokens.method(req, res)),
      tokens.url(req, res),
      color(tokens.status(req, res)),
      chalk.gray(tokens['response-time'](req, res) + ' ms')
    ].join(' ');
  })
);

// The vulnerable lab intentionally uses weak cookie settings to demonstrate risk.
app.use(
  '/vulnerable',
  session({
    secret: 'hardcoded-insecure-secret',
    resave: true,
    saveUninitialized: true,
    cookie: {
      httpOnly: false,
      secure: false,
      sameSite: false,
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

// The secure lab uses a server-side session store, safer cookie flags, and a timeout.
app.use(
  '/secure',
  helmet({
    contentSecurityPolicy: false
  })
);
app.use(
  '/secure',
  session({
    store: new SqliteSessionStore(),
    name: 'secure_lab_sid',
    secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000
    }
  })
);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.use('/vulnerable', vulnerableRoutes);
app.use('/secure', secureRoutes);

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'views', '404.html'));
});

app.use((err, req, res, next) => {
  console.error(chalk.red('[error]'), err);
  res.status(500).json({
    error: 'Something went wrong. Check the server logs for details.'
  });
});

async function start(port = PORT) {
  await ensureDatabase();

  return new Promise((resolve) => {
    // This training app contains deliberate vulnerabilities. Keep it on this PC only.
    const server = app.listen(port, HOST, () => {
      const address = server.address();
      const displayPort = typeof address === 'object' ? address.port : port;
      console.log(chalk.green.bold(`\nSQL Injection Attack, Fix, Verify running on http://${HOST}:${displayPort}`));
      console.log(chalk.yellow('Vulnerable lab:'), `http://localhost:${displayPort}/vulnerable/login`);
      console.log(chalk.blue('Secure lab:'), `http://localhost:${displayPort}/secure/login\n`);
      resolve(server);
    });
  });
}

if (require.main === module) {
  start().catch((err) => {
    console.error(chalk.red('[startup-error]'), err);
    process.exit(1);
  });
}

module.exports = { app, start };
