const multer = require('multer');
const os = require('os');

const MAX_UPLOAD_MB = parseInt(process.env.MAX_UPLOAD_MB || '25', 10);

// Multer's fileSize limit is the authoritative check (enforced server-side
// regardless of what the frontend pre-checks) per the confirmed decision.
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const isZip =
      file.mimetype === 'application/zip' ||
      file.mimetype === 'application/x-zip-compressed' ||
      file.originalname.toLowerCase().endsWith('.zip');
    if (!isZip) {
      return cb(new Error('Only .zip files are accepted'));
    }
    return cb(null, true);
  },
});

module.exports = { upload, MAX_UPLOAD_MB };
