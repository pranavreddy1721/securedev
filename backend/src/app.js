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

  // Security headers — Helmet is one of the exact things SecureDev checks
  // for in scanned projects, so it has to be present here too.
  app.use(helmet());

  // CORS locked to the configured frontend origin (Cloudflare Pages domain
  // in production), not a wildcard.
  app.use(
    cors({
      origin: process.env.CLIENT_ORIGIN,
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
