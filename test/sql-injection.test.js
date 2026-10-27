const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

// A fresh database makes each test run reproducible and leaves demo data alone.
const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sql-injection-lab-'));
process.env.LAB_DB_PATH = path.join(testDir, 'lab.sqlite');
process.env.SESSION_SECRET = 'test-only-secret-not-for-deployment';

const { db } = require('../database/db');
const { start } = require('../server');

let server;
let baseUrl;

before(async () => {
  server = await start(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  await new Promise((resolve, reject) => db.close((err) => err ? reject(err) : resolve()));
  fs.rmSync(testDir, { recursive: true, force: true });
});

async function login(route, username, password) {
  return fetch(`${baseUrl}/${route}/login`, {
    method: 'POST',
    body: new URLSearchParams({ username, password }),
    redirect: 'manual'
  });
}

function cookieFrom(response) {
  return response.headers.get('set-cookie')?.split(';', 1)[0];
}

test('the vulnerable login accepts the demonstration payload', async () => {
  const payload = "' OR '1'='1";
  const response = await login('vulnerable', payload, payload);

  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), '/vulnerable/dashboard');
  const cookie = cookieFrom(response);
  assert.ok(cookie, 'a successful login should establish a session');

  const dashboard = await fetch(`${baseUrl}/vulnerable/dashboard`, {
    headers: { cookie },
    redirect: 'manual'
  });
  assert.equal(dashboard.status, 200);
});

test('the secure login rejects the same payload and leaves the dashboard protected', async () => {
  const payload = "' OR '1'='1";
  const response = await login('secure', payload, payload);

  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), '/secure/login?error=1');

  const dashboard = await fetch(`${baseUrl}/secure/dashboard`, { redirect: 'manual' });
  assert.equal(dashboard.status, 302);
  assert.equal(dashboard.headers.get('location'), '/secure/login');
});

test('the secure login still accepts valid credentials', async () => {
  const response = await login('secure', 'admin', 'Admin123!');

  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), '/secure/dashboard');
  const cookie = cookieFrom(response);
  assert.ok(cookie);

  const dashboard = await fetch(`${baseUrl}/secure/dashboard`, {
    headers: { cookie },
    redirect: 'manual'
  });
  assert.equal(dashboard.status, 200);
});
