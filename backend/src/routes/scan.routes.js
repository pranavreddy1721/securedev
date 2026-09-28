const express = require('express');
const scanController = require('../controllers/scan.controller');
const { requireAuth } = require('../middleware/auth');
const { scanLimiter, apiLimiter } = require('../middleware/rateLimiter');
const { validateObjectId } = require('../middleware/validateObjectId');

const router = express.Router();

router.use(requireAuth);

router.post('/project/:projectId', validateObjectId('projectId'), scanLimiter, scanController.triggerScan);
router.get('/project/:projectId/history', validateObjectId('projectId'), apiLimiter, scanController.listScanHistory);
router.get('/:id', validateObjectId('id'), apiLimiter, scanController.getScan);
router.get('/:id/report', validateObjectId('id'), apiLimiter, scanController.downloadReport);

module.exports = router;
