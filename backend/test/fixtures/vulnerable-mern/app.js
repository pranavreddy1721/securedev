const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();
const upload = multer({ dest: 'uploads/' });

const JWT_SECRET = 'this-is-a-hardcoded-jwt-secret-12345';
const AWS_SECRET_ACCESS_KEY = 'abcdefghijklmnopqrstuvwxyz1234567890ABCD1234';

function requireAuth(req, res, next) { next(); }

// Intentionally authenticated but missing role/authorization middleware.
app.get('/admin/users', requireAuth, (req, res) => {
  console.log('Authorization token:', req.headers.authorization);
  res.json({ password: 'user-password', accessToken: JWT_SECRET });
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
