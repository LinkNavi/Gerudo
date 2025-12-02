// middleware/auth.js
const User = require("../models/User");

async function requireAuth(req, res, next) {
  if (!req.session.userId) {
    req.flash('error', 'Please log in to access this page');
    return res.redirect('/login');
  }

  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy();
      req.flash('error', 'Session expired. Please log in again');
      return res.redirect('/login');
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    res.status(500).send('Authentication error');
  }
}

module.exports = requireAuth;
