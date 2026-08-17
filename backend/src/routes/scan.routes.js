const express = require('express');
const scanController = require('../controllers/scan.controller');
const { requireAuth } = require('../middleware/auth');
const { scanLimiter, apiLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

router.use(requireAuth);

router.post('/project/:projectId', scanLimiter, scanController.triggerScan);
router.get('/project/:projectId/history', apiLimiter, scanController.listScanHistory);
router.get('/:id', apiLimiter, scanController.getScan);
router.get('/:id/report', apiLimiter, scanController.downloadReport);

module.exports = router;
