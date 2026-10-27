# SQL Injection: Attack, Fix, Verify

A local portfolio project that demonstrates an authentication bypass caused by SQL injection, replaces the unsafe query with a parameterized query, and verifies both behaviors with automated HTTP tests. It is adapted from my existing Vulnerable Web Application Lab.

## What to show at the job fair

| Step | Vulnerable route | Secure route |
| --- | --- | --- |
| Query | Builds SQL with the username and password text | Looks up a user with a parameterized query, then checks a bcrypt hash |
| Demonstration input | `' OR '1'='1` in both login fields | The same input |
| Result | Logs in without knowing the account password | Rejects the login |
| Regression check | Test confirms the bypass remains reproducible for the teaching example | Test confirms the bypass fails and a normal login still works |

The app binds to `127.0.0.1`, so the deliberately vulnerable route is available only on this computer. Use it only as a local training lab. Do not put it on a public server.

## Run it

Requirements: Node.js 18 or newer and npm. In PowerShell, use `npm.cmd` in place of `npm` if script execution blocks `npm.ps1`.

```text
git clone https://github.com/atulyado/SQL-Injection-Attack-Fix-Verify.git
cd SQL-Injection-Attack-Fix-Verify
npm ci
npm test
npm start
```

Open `http://127.0.0.1:3000` in a browser. The app creates `database/lab.sqlite` on first run; that file is ignored by Git. Set `PORT` if port 3000 is in use. Tests create and remove a separate temporary database, so they do not change the demo database.

For a fresh local demo database, stop the app, remove only `database/lab.sqlite`, and start it again. The startup code recreates the seeded lab accounts.

## Two minute live demo

1. Open **Vulnerable login**. Enter `' OR '1'='1` as both username and password. You reach the vulnerable dashboard without the admin password.
2. Open **Secure login** in another browser window. Enter the same strings. The app returns to the login page with an error.
3. Show the two query implementations in `routes/vulnerableRoutes.js` and `routes/secureRoutes.js`. Explain that the secure query sends the username as data, so the quote characters cannot alter the SQL statement.
4. Run `npm test`. Point out the tests for the vulnerable bypass, secure rejection, and valid secure login.

Seeded lab credentials for checking a normal login: vulnerable `admin` / `admin123`; secure `admin` / `Admin123!`. These are local demo accounts, never production credentials.

## Files worth showing

- [`routes/vulnerableRoutes.js`](routes/vulnerableRoutes.js): deliberately unsafe login query.
- [`routes/secureRoutes.js`](routes/secureRoutes.js): parameterized lookup and password hash verification.
- [`test/sql-injection.test.js`](test/sql-injection.test.js): end to end HTTP regression tests.
- [`FINDINGS.md`](FINDINGS.md): concise security case study and limitations.

The original lab also contains XSS, password storage, and session handling examples. This portfolio version focuses its explanation and tests on **SQL injection in login**.
