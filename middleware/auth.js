function requireVulnerableLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/vulnerable/login');
  }
  next();
}

function requireSecureLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/secure/login');
  }

  if (req.session.createdAt && Date.now() - req.session.createdAt > 15 * 60 * 1000) {
    req.session.destroy(() => res.redirect('/secure/login?timeout=1'));
    return;
  }

  next();
}

module.exports = { requireVulnerableLogin, requireSecureLogin };
