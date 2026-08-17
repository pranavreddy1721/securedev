const express = require('express');
const projectController = require('../controllers/project.controller');
const { requireAuth } = require('../middleware/auth');
const { upload } = require('../middleware/upload');
const { apiLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

router.use(requireAuth, apiLimiter);

router.get('/', projectController.listProjects);
router.get('/:id', projectController.getProject);
router.post('/zip', upload.single('project'), projectController.createFromZip);
router.post('/github', projectController.createFromGithub);
router.delete('/:id', projectController.deleteProject);

module.exports = router;
