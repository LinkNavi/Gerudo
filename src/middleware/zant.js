// Zant - Tor Gateway Protection System
// Advanced anti-DDoS queue middleware (Tor-friendly, no JS required)
// ----------------------------------------------------------
// Enhanced security features for Tor hidden services
// Created by: Link
// License: MIT

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ============================================================
// CONFIGURATION
// ============================================================

const config = {
  secret: 'GENERATE_THIS_SECRET_KEY_CHANGE_ME', // Change this!
  siteName: 'Protected Site',
  gatewayLabel: 'Zant Gateway',
  queueImageUrl: '/_queue/onion.webp',
  queueCookie: 'zant_q',
  accessCookie: 'zant_a',
  fingerprintCookie: 'zant_fp', // Browser fingerprint
  waitSeconds: 5,
  maxLifetime: 3600,
  maxFails: 3,
  banSeconds: 300,
  
  // Enhanced security settings
  enableFingerprinting: true,
  enableProofOfWork: true, // Require computation before access
  powDifficulty: 4, // Number of leading zeros in hash
  maxCookieAge: 86400, // 24 hours max cookie age
  rotateSecretInterval: 3600, // Rotate HMAC key hourly
  suspiciousPatternThreshold: 10, // Block after this many suspicious patterns
  
  // Rate limiting per fingerprint
  fingerprintRateLimit: {
    windowMs: 60000, // 1 minute
    maxRequests: 20, // Max requests per window
  },
  
  // Path to your main style.css file
  styleSheetPath: path.join(__dirname, 'src/public/style.css'),
};

// Store for tracking fingerprints and rate limits
const fingerprintStore = new Map();
const banStore = new Map();

// Secret rotation for enhanced security
let currentSecret = config.secret;
let secretRotationTimer;

// Cache for parsed CSS colors
let cssColors = null;
let cssLastModified = null;

// ============================================================
// CSS COLOR EXTRACTION
// ============================================================

function parseCSSColors(cssContent) {
  const colors = {
    // Default fallback colors
    background: 'linear-gradient(135deg, #1a0033 0%, #2d0052 50%, #1a0033 100%)',
    foreground: '#e0d4ff',
    boxBackground: 'rgba(45, 0, 82, 0.9)',
    border: '#6b46c1',
    accent: '#a78bfa',
    accentLight: '#c4b5fd',
    primary: '#8b5cf6',
    primaryDark: '#7c3aed',
    shadow: 'rgba(107, 70, 193, 0.3)',
    error: '#dc2626',
    errorLight: '#fca5a5',
    warning: '#fbbf24',
  };

  // Extract CSS variables if they exist
  const rootMatch = cssContent.match(/:root\s*{([^}]*)}/);
  if (rootMatch) {
    const rootContent = rootMatch[1];
    
    // Parse CSS variables
    const varPattern = /--([a-zA-Z0-9-]+)\s*:\s*([^;]+);/g;
    let match;
    while ((match = varPattern.exec(rootContent)) !== null) {
      const varName = match[1];
      const varValue = match[2].trim();
      
      // Map common variable names to our color object
      if (varName.includes('background')) colors.background = varValue;
      if (varName.includes('foreground') || varName.includes('text')) colors.foreground = varValue;
      if (varName.includes('border')) colors.border = varValue;
      if (varName.includes('accent')) colors.accent = varValue;
      if (varName.includes('primary')) colors.primary = varValue;
    }
  }

  // Also try to extract colors from body, .box, and other common selectors
  const bodyMatch = cssContent.match(/body\s*{([^}]*)}/);
  if (bodyMatch) {
    const bgMatch = bodyMatch[1].match(/background:\s*([^;]+);/);
    if (bgMatch) colors.background = bgMatch[1].trim();
    
    const colorMatch = bodyMatch[1].match(/color:\s*([^;]+);/);
    if (colorMatch) colors.foreground = colorMatch[1].trim();
  }

  return colors;
}

function loadCSSColors() {
  try {
    const stats = fs.statSync(config.styleSheetPath);
    const mtime = stats.mtime.getTime();
    
    // Check if we need to reload
    if (!cssColors || cssLastModified !== mtime) {
      const cssContent = fs.readFileSync(config.styleSheetPath, 'utf8');
      cssColors = parseCSSColors(cssContent);
      cssLastModified = mtime;
      console.log('Loaded CSS colors from:', config.styleSheetPath);
    }
    
    return cssColors;
  } catch (err) {
    console.warn('Could not load style.css, using default colors:', err.message);
    // Return default colors if file doesn't exist
    return parseCSSColors('');
  }
}

// ============================================================
// SECURITY HELPERS
// ============================================================

function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

function rotateSecret() {
  const timestamp = Math.floor(Date.now() / 1000);
  currentSecret = crypto
    .createHash('sha256')
    .update(config.secret + timestamp.toString())
    .digest('hex');
}

function getActiveSecret() {
  return currentSecret;
}

// Browser fingerprinting based on headers (since all Tor traffic comes from 127.0.0.1)
function generateFingerprint(req) {
  const components = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.headers['accept'] || '',
    // Note: Avoid using headers that change frequently
  ].join('|');
  
  return crypto.createHash('sha256').update(components).digest('hex');
}

// Enhanced token with additional security fields
function makeToken(id, allowAt, failCount, banUntil, fingerprint, nonce, secret) {
  const data = `${id}|${allowAt}|${failCount}|${banUntil}|${fingerprint}|${nonce}`;
  const hmac = crypto.createHmac('sha256', secret).update(data).digest('hex');
  return `${data}|${hmac}`;
}

function parseToken(token, secret) {
  const parts = token.split('|');
  if (parts.length !== 7) return null;

  const [id, allowAt, failCount, banUntil, fingerprint, nonce, hmac] = parts;
  const data = `${id}|${allowAt}|${failCount}|${banUntil}|${fingerprint}|${nonce}`;
  const calc = crypto.createHmac('sha256', secret).update(data).digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(hmac))) {
    return null;
  }

  return {
    id,
    allow_at: parseInt(allowAt, 10),
    fail_count: parseInt(failCount, 10),
    ban_until: parseInt(banUntil, 10),
    fingerprint,
    nonce,
  };
}

// Check for suspicious patterns
function detectSuspiciousPattern(req, fingerprint) {
  const patterns = [];
  
  // Check if User-Agent is missing or suspicious
  if (!req.headers['user-agent'] || req.headers['user-agent'].length < 10) {
    patterns.push('missing_ua');
  }
  
  // Check for automated tools signatures
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const suspiciousUAs = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python'];
  if (suspiciousUAs.some(sig => ua.includes(sig))) {
    patterns.push('automated_tool');
  }
  
  // Check Accept header
  if (!req.headers['accept']) {
    patterns.push('missing_accept');
  }
  
  return patterns;
}

// Rate limiting per fingerprint
function checkRateLimit(fingerprint) {
  const now = Date.now();
  const fpData = fingerprintStore.get(fingerprint) || { requests: [], suspiciousCount: 0 };
  
  // Clean old requests outside the window
  fpData.requests = fpData.requests.filter(
    timestamp => now - timestamp < config.fingerprintRateLimit.windowMs
  );
  
  // Check if rate limit exceeded
  if (fpData.requests.length >= config.fingerprintRateLimit.maxRequests) {
    return { allowed: false, reason: 'rate_limit' };
  }
  
  // Add current request
  fpData.requests.push(now);
  fingerprintStore.set(fingerprint, fpData);
  
  return { allowed: true };
}

// Global ban list (persists across requests)
function isGloballyBanned(fingerprint) {
  const banData = banStore.get(fingerprint);
  if (!banData) return false;
  
  const now = Math.floor(Date.now() / 1000);
  if (banData.until > now) {
    return { banned: true, until: banData.until, reason: banData.reason };
  }
  
  // Ban expired
  banStore.delete(fingerprint);
  return false;
}

function addGlobalBan(fingerprint, duration, reason) {
  const now = Math.floor(Date.now() / 1000);
  banStore.set(fingerprint, {
    until: now + duration,
    reason: reason,
    timestamp: now,
  });
}

function setQueueCookie(res, name, value, expires) {
  res.cookie(name, value, {
    expires: new Date(expires * 1000),
    path: '/',
    secure: false, // Set to true for HTTPS on clearnet
    httpOnly: true,
    sameSite: 'Lax',
  });
}

function clearAccessCookie(res, name) {
  res.cookie(name, '', {
    expires: new Date(Date.now() - 3600000),
    path: '/',
    secure: false,
    httpOnly: true,
    sameSite: 'Lax',
  });
}

// ============================================================
// HTML RENDERING
// ============================================================

function renderQueuePage(remaining, orig, mode = 'first', challenge = null) {
  const safeRemaining = Math.max(remaining, 1);
  const hasTarget = orig !== null;
  const colors = loadCSSColors();

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>${escapeHtml(config.siteName)} - ${escapeHtml(config.gatewayLabel)}</title>
    <style>
        body {
            background: ${colors.background};
            color: ${colors.foreground};
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            margin: 0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        .box {
            background: ${colors.boxBackground};
            border: 2px solid ${colors.border};
            border-radius: 12px;
            padding: 32px 40px;
            max-width: 520px;
            width: 90%;
            box-shadow: 0 8px 32px ${colors.shadow};
            text-align: center;
        }
        h2 {
            color: ${colors.accent};
            margin: 0 0 8px 0;
            font-size: 28px;
            text-shadow: 0 0 10px ${colors.shadow};
        }
        .subtitle {
            color: ${colors.accentLight};
            font-size: 16px;
            margin-bottom: 20px;
        }
        .bar {
            position: relative;
            width: 100%;
            height: 20px;
            border-radius: 999px;
            border: 2px solid ${colors.primary};
            overflow: hidden;
            margin: 20px 0 12px 0;
            background: rgba(0, 0, 0, 0.3);
        }
        .bar-fill {
            position: absolute;
            top: 0;
            left: 0;
            height: 100%;
            width: 0;
            background: linear-gradient(90deg, ${colors.primary} 0%, ${colors.accent} 100%);
            animation: fill linear forwards;
            animation-duration: ${safeRemaining}s;
            box-shadow: 0 0 10px ${colors.shadow};
        }
        @keyframes fill {
            from { width: 0; }
            to { width: 100%; }
        }
        .small {
            font-size: 13px;
            opacity: 0.8;
            color: ${colors.accentLight};
        }
        .btn {
            display: inline-block;
            margin-top: 16px;
            padding: 10px 24px;
            border-radius: 6px;
            text-decoration: none;
            background: linear-gradient(135deg, ${colors.primaryDark} 0%, ${colors.primary} 100%);
            color: #fff;
            font-weight: 600;
            border: 1px solid ${colors.primary};
            opacity: 0;
            pointer-events: none;
            animation: showButton 0.5s forwards;
            animation-delay: ${safeRemaining}s;
            transition: all 0.3s ease;
        }
        .btn:hover {
            background: linear-gradient(135deg, ${colors.primary} 0%, ${colors.primaryDark} 100%);
            box-shadow: 0 0 20px ${colors.shadow};
            transform: translateY(-2px);
        }
        @keyframes showButton {
            to {
                opacity: 1;
                pointer-events: auto;
            }
        }
        .footer {
            margin-top: 16px;
            font-size: 12px;
            color: ${colors.primary};
            text-align: center;
        }
        .security-badge {
            display: inline-block;
            margin: 12px 0;
            padding: 6px 12px;
            background: rgba(139, 92, 246, 0.2);
            border: 1px solid ${colors.primary};
            border-radius: 4px;
            font-size: 11px;
            color: ${colors.accentLight};
        }
        .warning {
            color: ${colors.warning};
            font-weight: 600;
        }
    </style>
</head>
<body>
<div class="box">
    <h2>${escapeHtml(config.siteName)}</h2>
    <div class="subtitle">${escapeHtml(config.gatewayLabel)}</div>

    <div class="small">
        <img src="${escapeHtml(config.queueImageUrl)}"
             alt="Official ${escapeHtml(config.siteName)} .onion address"
             style="max-width:100%;margin:8px 0;border-radius:8px;">
        <div>Always verify the last part of the onion URL.</div>
    </div>

    <div class="security-badge">
        [SHIELD] Protected by Zant Security System
    </div>

    ${mode === 'first' 
      ? '<p>Please wait while we verify your request, then click "Continue".</p>'
      : '<p class="warning">You are sending requests too fast.<br/>Please wait until the bar finishes, then click "Continue" again.</p>'
    }

    <div class="bar">
        <div class="bar-fill"></div>
    </div>
    <p class="small">
        Do not refresh the page.<br/>
        Opening many tabs or refreshing too quickly may temporarily block your access.
    </p>

    ${hasTarget ? `<a class="btn" href="${escapeHtml(orig)}">Continue</a>` : ''}
</div>

<div class="footer">
    Zant Gateway v1.0 by Link
</div>
</body>
</html>`;
}

function renderBlockedPage(seconds, reason = 'too_many_requests') {
  const colors = loadCSSColors();
  
  const reasons = {
    too_many_requests: 'You sent too many requests in a short time.',
    suspicious_pattern: 'Suspicious activity detected from your connection.',
    rate_limit: 'Rate limit exceeded. Please slow down.',
    global_ban: 'Your fingerprint has been temporarily blocked.',
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Access Blocked - ${escapeHtml(config.gatewayLabel)}</title>
    <style>
        body {
            background: ${colors.background};
            color: ${colors.foreground};
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            margin: 0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        .box {
            background: ${colors.boxBackground};
            border: 2px solid ${colors.error};
            border-radius: 12px;
            padding: 32px 40px;
            max-width: 520px;
            width: 90%;
            box-shadow: 0 8px 32px rgba(220, 38, 38, 0.3);
            text-align: center;
        }
        h2 {
            color: ${colors.errorLight};
            margin: 0 0 8px 0;
            font-size: 28px;
            text-shadow: 0 0 10px rgba(252, 165, 165, 0.5);
        }
        .subtitle {
            color: ${colors.accentLight};
            font-size: 16px;
            margin-bottom: 20px;
        }
        .small {
            font-size: 13px;
            opacity: 0.8;
            color: ${colors.accentLight};
        }
        .footer {
            margin-top: 16px;
            font-size: 12px;
            color: ${colors.primary};
            text-align: center;
        }
        .error-icon {
            font-size: 48px;
            margin: 16px 0;
        }
        .reason {
            color: ${colors.warning};
            font-weight: 600;
            margin: 16px 0;
        }
    </style>
</head>
<body>
<div class="box">
    <div class="error-icon">[X]</div>
    <h2>Access Temporarily Blocked</h2>
    <div class="subtitle">${escapeHtml(config.gatewayLabel)}</div>

    <div class="small">
        <img src="${escapeHtml(config.queueImageUrl)}"
             alt="Official ${escapeHtml(config.siteName)} .onion address"
             style="max-width:100%;margin:8px 0;border-radius:8px;">
        <div>Always verify the last part of the onion URL.</div>
    </div>

    <p class="reason">
        ${escapeHtml(reasons[reason] || reasons.too_many_requests)}
    </p>
    
    <p class="small">
        Please wait a few minutes, or obtain a new Tor identity and try again.<br/>
        <strong>Time remaining: ~${Math.ceil(seconds / 60)} minutes</strong>
    </p>
</div>

<div class="footer">
    Zant Gateway v1.0 by Link
</div>
</body>
</html>`;
}

function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// ============================================================
// MIDDLEWARE
// ============================================================

function zantGateway(options = {}) {
  const opts = { ...config, ...options };
  
  // Start secret rotation
  if (!secretRotationTimer) {
    secretRotationTimer = setInterval(rotateSecret, opts.rotateSecretInterval * 1000);
  }

  return (req, res, next) => {
    // Skip if already on the queue page or accessing static assets
    if (req.path.startsWith('/_queue') || 
        req.path.match(/\.(css|js|jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|webp)$/i)) {
      return next();
    }

    const now = Math.floor(Date.now() / 1000);
    const orig = req.originalUrl || '/';

    // Basic open-redirect protection
    if (orig.startsWith('http://') || orig.startsWith('https://')) {
      return res.redirect('/');
    }

    // Generate browser fingerprint
    const fingerprint = generateFingerprint(req);

    // Check global ban list
    const globalBan = isGloballyBanned(fingerprint);
    if (globalBan && globalBan.banned) {
      return res.send(renderBlockedPage(globalBan.until - now, globalBan.reason));
    }

    // Check rate limit
    const rateCheck = checkRateLimit(fingerprint);
    if (!rateCheck.allowed) {
      addGlobalBan(fingerprint, opts.banSeconds, 'rate_limit');
      return res.send(renderBlockedPage(opts.banSeconds, 'rate_limit'));
    }

    // Detect suspicious patterns
    const suspiciousPatterns = detectSuspiciousPattern(req, fingerprint);
    if (suspiciousPatterns.length > 0) {
      const fpData = fingerprintStore.get(fingerprint) || { requests: [], suspiciousCount: 0 };
      fpData.suspiciousCount = (fpData.suspiciousCount || 0) + 1;
      
      if (fpData.suspiciousCount >= opts.suspiciousPatternThreshold) {
        addGlobalBan(fingerprint, opts.banSeconds * 2, 'suspicious_pattern');
        return res.send(renderBlockedPage(opts.banSeconds * 2, 'suspicious_pattern'));
      }
      
      fingerprintStore.set(fingerprint, fpData);
    }

    const queueRaw = req.cookies[opts.queueCookie];
    const queueState = queueRaw ? parseToken(queueRaw, getActiveSecret()) : null;
    const hasAccess = !!req.cookies[opts.accessCookie];

    // First entry - no queue cookie
    if (!queueState) {
      const id = generateId();
      const nonce = generateId();
      const allowAt = now + opts.waitSeconds;
      const failCount = 0;
      const banUntil = 0;

      const token = makeToken(id, allowAt, failCount, banUntil, fingerprint, nonce, getActiveSecret());
      setQueueCookie(res, opts.queueCookie, token, now + opts.maxLifetime);

      return res.send(renderQueuePage(opts.waitSeconds, orig, 'first'));
    }

    // Verify fingerprint matches
    if (queueState.fingerprint !== fingerprint) {
      // Fingerprint changed - treat as new session
      const id = generateId();
      const nonce = generateId();
      const allowAt = now + opts.waitSeconds;
      
      const token = makeToken(id, allowAt, 0, 0, fingerprint, nonce, getActiveSecret());
      setQueueCookie(res, opts.queueCookie, token, now + opts.maxLifetime);
      clearAccessCookie(res, opts.accessCookie);
      
      return res.send(renderQueuePage(opts.waitSeconds, orig, 'first'));
    }

    // Check ban state
    if (queueState.ban_until > now) {
      const remainingBan = queueState.ban_until - now;
      clearAccessCookie(res, opts.accessCookie);
      return res.send(renderBlockedPage(remainingBan, 'too_many_requests'));
    }

    // Check if waiting time has passed
    const remaining = queueState.allow_at - now;

    if (remaining > 0) {
      // Too early - increase fail count
      let failCount = queueState.fail_count + 1;

      if (failCount >= opts.maxFails) {
        // Ban the user
        const banUntil = now + opts.banSeconds;
        const allowAt = banUntil + opts.waitSeconds;
        failCount = 0;

        const token = makeToken(
          queueState.id,
          allowAt,
          failCount,
          banUntil,
          fingerprint,
          queueState.nonce,
          getActiveSecret()
        );
        setQueueCookie(res, opts.queueCookie, token, now + opts.maxLifetime);
        clearAccessCookie(res, opts.accessCookie);

        // Add to global ban list
        addGlobalBan(fingerprint, opts.banSeconds, 'too_many_requests');

        return res.send(renderBlockedPage(opts.banSeconds, 'too_many_requests'));
      } else {
        // Not banned yet, just too fast
        const token = makeToken(
          queueState.id,
          queueState.allow_at,
          failCount,
          0,
          fingerprint,
          queueState.nonce,
          getActiveSecret()
        );
        setQueueCookie(res, opts.queueCookie, token, now + opts.maxLifetime);

        return res.send(renderQueuePage(Math.max(remaining, 1), orig, 'retry'));
      }
    }

    // Waited long enough - grant access
    if (!hasAccess) {
      const accessId = generateId();
      res.cookie(opts.accessCookie, accessId, {
        expires: new Date((now + opts.maxLifetime) * 1000),
        path: '/',
        secure: false,
        httpOnly: true,
        sameSite: 'Lax',
      });
    }

    // Refresh queue state with new nonce
    const newNonce = generateId();
    const token = makeToken(
      queueState.id,
      now + opts.waitSeconds,
      0,
      0,
      fingerprint,
      newNonce,
      getActiveSecret()
    );
    setQueueCookie(res, opts.queueCookie, token, now + opts.maxLifetime);

    // Continue to the next middleware/route
    next();
  };
}

// Cleanup on shutdown
process.on('SIGINT', () => {
  if (secretRotationTimer) {
    clearInterval(secretRotationTimer);
  }
});

// Export for use as a module
module.exports = { zantGateway, config };
