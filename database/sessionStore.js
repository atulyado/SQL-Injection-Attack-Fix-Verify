const session = require('express-session');
const { db } = require('./db');

class SqliteSessionStore extends session.Store {
  constructor() {
    super();
    db.run(`
      CREATE TABLE IF NOT EXISTS secure_sessions (
        sid TEXT PRIMARY KEY,
        session_json TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `);
  }

  get(sid, callback) {
    db.get('SELECT session_json, expires_at FROM secure_sessions WHERE sid = ?', [sid], (err, row) => {
      if (err) return callback(err);
      if (!row) return callback(null, null);

      if (row.expires_at <= Date.now()) {
        return this.destroy(sid, () => callback(null, null));
      }

      try {
        callback(null, JSON.parse(row.session_json));
      } catch (parseError) {
        callback(parseError);
      }
    });
  }

  set(sid, sess, callback = () => {}) {
    const expires = sess.cookie && sess.cookie.expires
      ? new Date(sess.cookie.expires).getTime()
      : Date.now() + 15 * 60 * 1000;

    db.run(
      `
        INSERT INTO secure_sessions (sid, session_json, expires_at)
        VALUES (?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET
          session_json = excluded.session_json,
          expires_at = excluded.expires_at
      `,
      [sid, JSON.stringify(sess), expires],
      callback
    );
  }

  destroy(sid, callback = () => {}) {
    db.run('DELETE FROM secure_sessions WHERE sid = ?', [sid], callback);
  }

  touch(sid, sess, callback = () => {}) {
    const expires = sess.cookie && sess.cookie.expires
      ? new Date(sess.cookie.expires).getTime()
      : Date.now() + 15 * 60 * 1000;

    db.run('UPDATE secure_sessions SET expires_at = ? WHERE sid = ?', [expires, sid], callback);
  }
}

module.exports = SqliteSessionStore;
