const express = require('express');
const githubController = require('../controllers/github.controller');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/connect', requireAuth, githubController.connectStart);
// Callback is hit directly by GitHub's redirect — no Bearer header available,
// auth is instead recovered via the signed `state` param (see controller).
router.get('/callback', githubController.connectCallback);
router.post('/disconnect', requireAuth, githubController.disconnect);
router.get('/repos', requireAuth, githubController.listRepos);

module.exports = router;
