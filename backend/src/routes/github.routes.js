const express = require('express');
const githubController = require('../controllers/github.controller');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/connect', requireAuth, githubController.connectStart);
// Callback is hit directly by GitHub's redirect — no Bearer header available.
// Auth is recovered via the short-lived OAuth state created in connectStart.
router.get('/callback', githubController.connectCallback);
router.get('/status', requireAuth, githubController.status);
router.post('/disconnect', requireAuth, githubController.disconnect);
router.get('/repos', requireAuth, githubController.listRepos);

module.exports = router;
