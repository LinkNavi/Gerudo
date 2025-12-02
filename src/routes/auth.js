const express = require("express");
const bcrypt = require("bcrypt");
const User = require("../models/User");

const router = express.Router();

// ============================================================
// VALIDATION HELPERS
// ============================================================

function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Username is required' };
  }
  
  if (username.length < 3) {
    return { valid: false, error: 'Username must be at least 3 characters' };
  }
  
  if (username.length > 20) {
    return { valid: false, error: 'Username must be less than 20 characters' };
  }
  
  // Only allow alphanumeric and underscores
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return { valid: false, error: 'Username can only contain letters, numbers, and underscores' };
  }
  
  return { valid: true };
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required' };
  }
  
  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters' };
  }
  
  if (password.length > 128) {
    return { valid: false, error: 'Password is too long' };
  }
  
  return { valid: true };
}

// ============================================================
// SIGNUP ROUTE
// ============================================================

router.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Validate username
    const usernameValidation = validateUsername(username);
    if (!usernameValidation.valid) {
      req.flash('error', usernameValidation.error);
      return res.redirect('/signup');
    }
    
    // Validate password
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      req.flash('error', passwordValidation.error);
      return res.redirect('/signup');
    }
    
    // Check if user already exists (AWAIT THIS!)
    const existingUser = await User.findByUsername(username);
    if (existingUser) {
      req.flash('error', 'Username already taken');
      return res.redirect('/signup');
    }
    
    // Hash password (bcrypt 12 rounds is good balance of security/speed)
    const passwordHash = await bcrypt.hash(password, 12);
    
    // Create user (AWAIT THIS!)
    const user = await User.create({ username, passwordHash });
    
    // Regenerate session to prevent session fixation attacks
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        req.flash('error', 'Failed to create session');
        return res.redirect('/signup');
      }
      
      req.session.userId = user.id;
      req.flash('success', `Welcome to Gerudo, ${username}!`);
      res.redirect('/dashboard');
    });
    
  } catch (err) {
    console.error('Signup error:', err);
    req.flash('error', 'An error occurred during signup');
    res.redirect('/signup');
  }
});

// ============================================================
// LOGIN ROUTE
// ============================================================

router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Basic validation
    if (!username || !password) {
      req.flash('error', 'Username and password are required');
      return res.redirect('/login');
    }
    
    // Find user (AWAIT THIS!)
    const user = await User.findByUsername(username);
    if (!user) {
      // Don't reveal whether username exists
      req.flash('error', 'Invalid username or password');
      return res.redirect('/login');
    }
    
    // Verify password
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      req.flash('error', 'Invalid username or password');
      return res.redirect('/login');
    }
    
    // Regenerate session
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        req.flash('error', 'Failed to create session');
        return res.redirect('/login');
      }
      
      req.session.userId = user.id;
      req.flash('success', `Welcome back, ${username}!`);
      res.redirect('/dashboard');
    });
    
  } catch (err) {
    console.error('Login error:', err);
    req.flash('error', 'An error occurred during login');
    res.redirect('/login');
  }
});

// ============================================================
// LOGOUT ROUTE
// ============================================================

router.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      req.flash('error', 'Failed to logout');
      return res.redirect('/');
    }
    
    res.redirect('/');
  });
});

module.exports = router;
