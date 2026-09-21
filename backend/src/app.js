const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/auth.routes');
const githubRoutes = require('./routes/github.routes');
const projectRoutes = require('./routes/project.routes');
const scanRoutes = require('./routes/scan.routes');
const { errorHandler } = require('./middleware/errorHandler');

function createApp() {
  const app = express();

  // Render sits behind a reverse proxy and forwards the original client IP in
  // X-Forwarded-For. Trust the single proxy hop so express-rate-limit can
  // safely and correctly identify clients without validation errors.
  app.set('trust proxy', 1);

  // Security headers — Helmet is one of the exact things SecureDev checks
  // for in scanned projects, so it has to be present here too.
  app.use(helmet());

  // CORS: normalize configured origins so a trailing slash in Render's
  // CLIENT_ORIGIN does not break browser preflight requests. Multiple origins
  // can be supplied as a comma-separated environment variable.
  const configuredOrigins = (process.env.CLIENT_ORIGIN || '')
    .split(',')
    .map((origin) => origin.trim().replace(/\/+$/, ''))
    .filter(Boolean);

  const allowedOrigins = new Set([
    ...configuredOrigins,
    'https://securedev.pages.dev',
    'http://localhost:5173',
    'http://localhost:4173',
  ]);

  app.use(
    cors({
      origin(origin, callback) {
        // Non-browser/server-to-server requests do not send an Origin header.
        if (!origin) return callback(null, true);

        const normalizedOrigin = origin.trim().replace(/\/+$/, '');
        if (allowedOrigins.has(normalizedOrigin)) {
          return callback(null, true);
        }

        return callback(new Error('CORS origin not allowed'));
      },
      credentials: true,
    })
  );

  app.use(express.json({ limit: '2mb' }));
  app.use(cookieParser());
  app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

  app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

  app.use('/api/auth', authRoutes);
  app.use('/api/github', githubRoutes);
  app.use('/api/projects', projectRoutes);
  app.use('/api/scans', scanRoutes);

  app.use((req, res) => res.status(404).json({ error: 'Not found' }));
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
