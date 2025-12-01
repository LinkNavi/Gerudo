// middleware/auth.js
const User = require("../models/User");

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).send("Unauthorized");

  const user = User.findById(req.session.userId);
  if (!user) return res.status(401).send("Unauthorized");

  req.user = user;
  next();
}

module.exports = requireAuth;
