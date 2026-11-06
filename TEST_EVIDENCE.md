# SQL injection test evidence

Verified locally on 6 November 2026 against this repository's intentionally vulnerable application. This is HTTP test evidence, **not a Burp Suite capture**.

## Scope and method

- Target: the app started by `test/sql-injection.test.js` on `127.0.0.1` with a fresh temporary SQLite database.
- Request: form-encoded `POST /vulnerable/login` or `POST /secure/login`.
- Demonstration input: `' OR '1'='1` in both username and password fields.
- Command: `npm.cmd test`.

## Observed results

| Check | Observed HTTP behavior | Result |
| --- | --- | --- |
| Vulnerable login, demonstration input | `302` to `/vulnerable/dashboard`; authenticated request to dashboard returned `200` | Authentication bypass reproduced |
| Secure login, same input | `302` to `/secure/login?error=1`; unauthenticated dashboard request redirected to `/secure/login` | Bypass rejected |
| Secure login, valid seeded credentials | `302` to `/secure/dashboard`; authenticated dashboard request returned `200` | Normal login preserved |

The test runner reported **3 passed, 0 failed**. See [`test/sql-injection.test.js`](test/sql-injection.test.js) for the executable assertions and [`FINDINGS.md`](FINDINGS.md) for the cause, impact, fix, and limitations.

## Burp Suite evidence still needed

This repository does not contain a saved Burp request/response or Burp screenshot. To support a resume claim that Burp Suite was used for this *specific* project, repeat the three checks in Burp Repeater against the local app and save redacted request/response evidence. Remove session cookies and any secrets before publication. Until then, describe these as automated HTTP tests rather than Burp tests.
