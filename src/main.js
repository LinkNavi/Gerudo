require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const helmet = require("helmet");
const compression = require("compression");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const nunjucks = require("nunjucks");
const path = require("path");
const cookieParser = require('cookie-parser');

const User = require("./models/User");
const { zantGateway } = require('./middleware/zant');
const authRoutes = require("./routes/auth");
const frontendRoutes = require("./routes/frontend");
const dashboardRoutes = require("./routes/dashboard");

const app = express();

// ============================================================
// NUNJUCKS TEMPLATE ENGINE SETUP
// ============================================================
const viewsPath = path.join(__dirname, "views");
const env = nunjucks.configure(viewsPath, {
  autoescape: true,
  express: app,
  watch: process.env.NODE_ENV !== 'production', // Only watch in dev
});

// Add custom filters for templates
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
// BASIC MIDDLEWARE (Order matters!)
// ============================================================

// 1. Logging - should be first to log everything
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan("dev"));
}

// 2. Security headers
app.use(helmet({
  contentSecurityPolicy: false, // Disable for now, can configure later
}));

// 3. Compression
app.use(compression());

// 4. Body parsers - needed for forms and JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 5. Cookie parser - needed before session
app.use(cookieParser());

// ============================================================
// STATIC FILES - Before Zant to avoid queuing CSS/JS
// ============================================================
app.use(express.static(path.join(__dirname, "public")));

// Special route for Zant queue image
app.get('/_queue/onion.webp', (req, res) => {
  res.sendFile(path.join(__dirname, 'onion.webp'));
});

// ============================================================
// ZANT GATEWAY PROTECTION
// ============================================================
// Exclude static assets and certain paths from Zant
app.use((req, res, next) => {
  // Skip Zant for static files and special routes
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
// SESSION MANAGEMENT
// ============================================================
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.db", dir: "." }),
    secret: process.env.SESSION_SECRET || "change-me-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: { 
      secure: process.env.NODE_ENV === 'production', // Only HTTPS in prod
      httpOnly: true, 
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

// ============================================================
// USER CONTEXT MIDDLEWARE
// ============================================================
// This makes the current user available in all templates
app.use(async (req, res, next) => {
  res.locals.year = new Date().getFullYear();
  res.locals.currentPath = req.path;
  
  if (req.session.userId) {
    try {
      const user = User.findById(req.session.userId);
      res.locals.user = user;
      req.user = user; // Also attach to request object
    } catch (err) {
      console.error('Error loading user:', err);
      res.locals.user = null;
    }
  } else {
    res.locals.user = null;
  }
  next();
});

// ============================================================
// FLASH MESSAGES MIDDLEWARE
// ============================================================
// Simple flash message system for success/error notifications
app.use((req, res, next) => {
  res.locals.flash = req.session.flash || {};
  req.session.flash = {};
  
  // Helper function to set flash messages
  req.flash = (type, message) => {
    req.session.flash = req.session.flash || {};
    req.session.flash[type] = message;
  };
  
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

// 404 Handler
app.use((req, res) => {
  res.status(404).render("404.njk", { 
    title: "Page Not Found",
    path: req.path 
  });
});

// Error Handler
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
});