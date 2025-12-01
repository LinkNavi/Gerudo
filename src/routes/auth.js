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
      return res.status(400).json({ 
        error: usernameValidation.error 
      });
    }
    
    // Validate password
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ 
        error: passwordValidation.error 
      });
    }
    
    // Check if user already exists
    const existingUser = User.findByUsername(username);
    if (existingUser) {
      return res.status(400).json({ 
        error: 'Username already taken' 
      });
    }
    
    // Hash password (bcrypt 12 rounds is good balance of security/speed)
    const passwordHash = await bcrypt.hash(password, 12);
    
    // Create user
    const user = User.create({ username, passwordHash });
    
    // Regenerate session to prevent session fixation attacks
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).json({ 
          error: 'Failed to create session' 
        });
      }
      
      req.session.userId = user.id;
      req.flash('success', `Welcome to Gerudo, ${username}!`);
      
      res.json({ 
        success: true,
        redirect: '/dashboard'
      });
    });
    
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ 
      error: 'An error occurred during signup' 
    });
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
      return res.status(400).json({ 
        error: 'Username and password are required' 
      });
    }
    
    // Find user
    const user = User.findByUsername(username);
    if (!user) {
      // Don't reveal whether username exists
      return res.status(401).json({ 
        error: 'Invalid username or password' 
      });
    }
    
    // Verify password
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ 
        error: 'Invalid username or password' 
      });
    }
    
    // Regenerate session
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).json({ 
          error: 'Failed to create session' 
        });
      }
      
      req.session.userId = user.id;
      req.flash('success', `Welcome back, ${username}!`);
      
      res.json({ 
        success: true,
        redirect: '/dashboard'
      });
    });
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      error: 'An error occurred during login' 
    });
  }
});

// ============================================================
// LOGOUT ROUTE
// ============================================================

router.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ 
        error: 'Failed to logout' 
      });
    }
    
    res.json({ 
      success: true,
      redirect: '/'
    });
  });
});

module.exports = router;