# Security finding: SQL injection in login

## Scope

Local Node.js and SQLite training application in this repository. The affected endpoint is `POST /vulnerable/login`. The comparison endpoint is `POST /secure/login`. No external system was tested.

## Finding and impact

The vulnerable login builds its SQL statement by inserting the submitted username and password directly into the statement text:

```js
const sql = `SELECT * FROM vulnerable_users WHERE username = '${username}' AND password = '${password}'`;
const user = await get(sql);
```

The database treats SQL syntax in those inputs as part of the query. In the seeded local lab, entering `' OR '1'='1` in **both** fields causes the query to return a user, so the app creates an authenticated session without knowing the password. The demonstrated impact is an authentication bypass in the vulnerable track.

## Reproduction

1. Start the app locally with `npm.cmd start`.
2. Open `http://127.0.0.1:3000/vulnerable/login`.
3. Enter `' OR '1'='1` in both login fields and submit.
4. Observe a redirect to `/vulnerable/dashboard` and access to the dashboard.

This is a deliberately vulnerable teaching route. The proof uses only the included demo database.

## Fix

The secure route separates SQL code from user input and verifies the submitted password against a stored bcrypt hash:

```js
const user = await get('SELECT * FROM secure_users WHERE username = ?', [username]);
const isValid = user ? await bcrypt.compare(password, user.password_hash) : false;
```

The database receives the username as a bound value. Quote characters in it remain data. The secure route also avoids storing a plain text password.

## Verification

Run `npm.cmd test`. The HTTP tests check that:

1. The payload reaches the vulnerable dashboard.
2. The same payload fails on the secure route and does not grant dashboard access.
3. Correct credentials still grant access on the secure route.

The tests use a fresh temporary SQLite database and exercise the app through HTTP. They verify this demonstration path; they are not a complete security assessment of the application.

## Limitations and next work

- The vulnerable route still contains other intentional weaknesses from the original teaching lab. Its code must remain local and must never be deployed as an application template.
- The secure route is a comparison example, not a production ready authentication service. A production system needs deployment specific settings for HTTPS, session secrets, account recovery, monitoring, and further security review.
- Automated coverage focuses on one SQL injection payload and a normal login. More inputs and the registration route can be assessed separately.
