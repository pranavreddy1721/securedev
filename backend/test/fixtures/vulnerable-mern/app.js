const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();
const upload = multer({ dest: 'uploads/' });

// Credentials are intentionally absent from the checked-in fixture. Secret
// scanner tests create synthetic values at runtime so this repository never
// needs to contain credential-shaped strings.
const JWT_SECRET = process.env.JWT_SECRET || '';
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY || '';

function requireAuth(req, res, next) { next(); }

// Intentionally authenticated but missing role/authorization middleware.
app.get('/admin/users', requireAuth, (req, res) => {
  console.log('Authorization token:', req.headers.authorization);
  res.json({ password: null, accessToken: JWT_SECRET });
});

app.post('/upload', upload.single('file'), (req, res) => {
  const target = path.join('uploads', req.body.filename);
  res.send(target);
});

// Intentionally unsafe dynamic code execution for Semgrep integration coverage.
app.get('/evaluate', (req, res) => {
  const result = eval("securedev-test");
  res.send(String(result));
});

module.exports = app;
