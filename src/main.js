require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const helmet = require("helmet");
const compression = require("compression");
const session = require("express-session");
const pgSession = require('connect-pg-simple')(session);
const nunjucks = require("nunjucks");
const path = require("path");
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const { pool, initDatabase } = require("./db");
const User = require("./models/User");
const { zantGateway } = require('./middleware/zant');
const authRoutes = require("./routes/auth");
const frontendRoutes = require("./routes/frontend");
const dashboardRoutes = require("./routes/dashboard");

const app = express();

// ============================================================
// INITIALIZE DATABASE
// ============================================================
initDatabase().catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});

// ============================================================
// NUNJUCKS TEMPLATE ENGINE SETUP
// ============================================================
const viewsPath = path.join(__dirname, "views");
const env = nunjucks.configure(viewsPath, {
  autoescape: true,
  express: app,
  watch: process.env.NODE_ENV !== 'production',
});

env.addFilter("date", function(date, format) {
  const d = date === "now" ? new Date() : new Date(date);
  if (format === "YYYY") return d.getFullYear();
  if (format === "short") {
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }
  return d.toLocaleDateString();
});

env.addFilter("truncate", function(str, length) {
  if (!str || str.length <= length) return str;
  return str.substring(0, length) + "...";
});

// ============================================================
// BASIC MIDDLEWARE
// ============================================================
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan("dev"));
}

// Enhanced helmet configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for flash messages
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
}));

app.use(compression());
app.use(express.json({ limit: '10mb' })); // Limit payload size
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// ============================================================
// RATE LIMITING (Basic)
// ============================================================
const requestCounts = new Map();

app.use((req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  
  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, []);
  }
  
  const requests = requestCounts.get(ip);
  // Keep only requests from the last minute
  const recentRequests = requests.filter(time => now - time < 60000);
  
  if (recentRequests.length > 100) {
    return res.status(429).send('Too many requests');
  }
  
  recentRequests.push(now);
  requestCounts.set(ip, recentRequests);
  
  // Cleanup old entries periodically
  if (Math.random() < 0.01) {
    for (const [key, value] of requestCounts.entries()) {
      if (value.length === 0 || now - value[value.length - 1] > 300000) {
        requestCounts.delete(key);
      }
    }
  }
  
  next();
});

// ============================================================
// STATIC FILES
// ============================================================
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: '1d',
  etag: true,
}));

app.get('/_queue/onion.webp', (req, res) => {
  res.sendFile(path.join(__dirname, 'onion.webp'));
});

// ============================================================
// ZANT GATEWAY PROTECTION
// ============================================================
app.use((req, res, next) => {
  const skipPaths = [
    /\.(css|js|jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|webp|map)$/i,
    /^\/_queue\//,
    /^\/favicon\.ico$/,
  ];
  
  if (skipPaths.some(pattern => pattern.test(req.path))) {
    return next();
  }
  
  zantGateway({
    secret: process.env.ZANT_SECRET || 'replace-this-with-a-long-random-secret',
    siteName: 'Gerudo',
    waitSeconds: 5,
    maxFails: 3,
    banSeconds: 300,
    enableFingerprinting: true,
    suspiciousPatternThreshold: 10
  })(req, res, next);
});

// ============================================================
// SESSION MANAGEMENT (PostgreSQL)
// ============================================================
app.use(
  session({
    store: new pgSession({
      pool: pool,
      tableName: 'session',
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    name: 'gerudo.sid', // Custom session cookie name
    cookie: { 
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true, 
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

// ============================================================
// USER CONTEXT MIDDLEWARE
// ============================================================
app.use(async (req, res, next) => {
  res.locals.year = new Date().getFullYear();
  res.locals.currentPath = req.path;
  
  if (req.session.userId) {
    try {
      const user = await User.findById(req.session.userId);
      res.locals.user = user;
      req.user = user;
    } catch (err) {
      console.error('Error loading user:', err);
      res.locals.user = null;
      req.session.destroy(); // Clear invalid session
    }
  } else {
    res.locals.user = null;
  }
  next();
});

// ============================================================
// FLASH MESSAGES MIDDLEWARE
// ============================================================
app.use((req, res, next) => {
  res.locals.flash = req.session.flash || {};
  req.session.flash = {};
  
  req.flash = (type, message) => {
    req.session.flash = req.session.flash || {};
    req.session.flash[type] = message;
  };
  
  next();
});

// ============================================================
// SECURITY HEADERS
// ============================================================
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Permissions policy
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  next();
});

// ============================================================
// ROUTES
// ============================================================
app.use("/", frontendRoutes);
app.use("/auth", authRoutes);
app.use("/dashboard", dashboardRoutes);

// ============================================================
// ERROR HANDLING
// ============================================================
app.use((req, res) => {
  res.status(404).render("404.njk", { 
    title: "Page Not Found",
    path: req.path 
  });
});

app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'Something went wrong' 
    : err.message;
    
  res.status(err.status || 500).render("error.njk", {
    title: "Error",
    message: message,
    error: process.env.NODE_ENV === 'production' ? {} : err
  });
});

// ============================================================
// SERVER START
// ============================================================
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";

app.listen(PORT, HOST, () => {
  console.log(`🚀 Gerudo server running on http://${HOST}:${PORT}`);
  console.log(`📁 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️  Database: PostgreSQL`);
  console.log(`🛡️  Zant Gateway: Active`);
});

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================
const gracefulShutdown = async () => {
  console.log('Shutting down gracefully...');
  
  try {
    await pool.end();
    console.log('Database connections closed');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
