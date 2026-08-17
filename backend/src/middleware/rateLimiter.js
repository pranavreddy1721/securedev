const rateLimit = require('express-rate-limit');

// Tighter limit on login/signup to blunt brute-force / credential-stuffing attempts.
// This is one of the things SecureDev itself is checked against (Broken Authentication),
// so the app has to practice what it scans for.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many auth attempts. Please try again later.' },
});

// Looser limit for general API routes.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

// Scans are expensive (spawn subprocesses) — throttle harder.
const scanLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scan requests. Please wait before starting another scan.' },
});

module.exports = { authLimiter, apiLimiter, scanLimiter };
