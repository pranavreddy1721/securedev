const fs = require('fs/promises');
const path = require('path');
const Project = require('../models/Project');
const Scan = require('../models/Scan');

async function listProjects(req, res, next) {
  try {
    const projects = await Project.find({ owner: req.userId }).sort({ createdAt: -1 });
    return res.json({ projects });
  } catch (err) {
    return next(err);
  }
}

async function getProject(req, res, next) {
  try {
    const project = await Project.findOne({ _id: req.params.id, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    return res.json({ project });
  } catch (err) {
    return next(err);
  }
}

/**
 * Creates a project record from an uploaded zip. The actual file stays
 * wherever multer put it (OS temp dir) until the scan controller extracts
 * and then deletes it — this endpoint just registers metadata.
 */
async function createFromZip(req, res, next) {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No zip file uploaded (field name must be "project")' });
    }

    const project = await Project.create({
      owner: req.userId,
      name: req.body.name || req.file.originalname.replace(/\.zip$/i, ''),
      source: {
        type: 'zip',
        originalFilename: req.file.originalname,
        sizeBytes: req.file.size,
      },
    });

    // Return the multer temp path so the scan trigger endpoint can find it —
    // in a multi-instance deployment this would need to move to shared/object
    // storage; fine for a single Render instance in v1.
    return res.status(201).json({ project, uploadedFilePath: req.file.path });
  } catch (err) {
    // Clean up the uploaded temp file if project creation failed
    if (req.file?.path) {
      await fs.unlink(req.file.path).catch(() => {});
    }
    return next(err);
  }
}

async function createFromGithub(req, res, next) {
  try {
    const { repoFullName, repoUrl, defaultBranch } = req.body;
    if (!repoFullName || !repoUrl) {
      return res.status(400).json({ error: 'repoFullName and repoUrl are required' });
    }

    const project = await Project.create({
      owner: req.userId,
      name: req.body.name || repoFullName,
      source: {
        type: 'github',
        repoFullName,
        repoUrl,
        defaultBranch: defaultBranch || 'main',
      },
    });

    return res.status(201).json({ project });
  } catch (err) {
    return next(err);
  }
}

async function deleteProject(req, res, next) {
  try {
    const project = await Project.findOneAndDelete({ _id: req.params.id, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    await Scan.deleteMany({ project: project._id });
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
}

module.exports = { listProjects, getProject, createFromZip, createFromGithub, deleteProject };
