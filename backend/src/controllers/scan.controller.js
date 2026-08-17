const os = require('os');
const path = require('path');
const fs = require('fs/promises');
const Project = require('../models/Project');
const Scan = require('../models/Scan');
const User = require('../models/User');
const { runOrchestratedScan, createTempDir } = require('../orchestrator/scanOrchestrator');
const { safeExtract } = require('../utils/zipExtractor');
const { cloneRepo } = require('../utils/repoCloner');
const { decrypt } = require('../utils/crypto');
const { generateScanPdf } = require('../reports/pdfGenerator');

/**
 * Triggers a new scan for a project. Prepares a temp working directory
 * (extract zip, or clone repo) synchronously, then kicks off the actual
 * scan orchestration asynchronously so the request returns quickly with a
 * "queued/running" scan the client can poll — a full job queue (Bull/Redis)
 * is deliberately out of scope for v1 per the confirmed execution model.
 */
async function triggerScan(req, res, next) {
  try {
    const project = await Project.findOne({ _id: req.params.projectId, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const scan = await Scan.create({ project: project._id, owner: req.userId, status: 'queued' });

    let workDir;
    try {
      workDir = await createTempDir();

      if (project.source.type === 'zip') {
        const { uploadedFilePath } = req.body;
        if (!uploadedFilePath || !uploadedFilePath.startsWith(os.tmpdir())) {
          throw new Error('Invalid or missing uploadedFilePath for zip project');
        }
        safeExtract(uploadedFilePath, workDir);
        await fs.unlink(uploadedFilePath).catch(() => {});
      } else if (project.source.type === 'github') {
        const user = await User.findById(req.userId).select('+github.accessTokenEncrypted');
        if (!user?.github?.accessTokenEncrypted) {
          throw new Error('GitHub is not connected for this account');
        }
        const accessToken = decrypt(user.github.accessTokenEncrypted);
        await cloneRepo({
          cloneUrl: project.source.repoUrl,
          accessToken,
          branch: project.source.defaultBranch,
          destDir: workDir,
        });
      } else {
        throw new Error(`Unknown project source type: ${project.source.type}`);
      }
    } catch (prepErr) {
      scan.status = 'failed';
      scan.error = `Failed to prepare project files: ${prepErr.message}`;
      await scan.save();
      return res.status(202).json({ scan }); // scan record exists but failed immediately
    }

    // Fire and forget — client polls GET /api/scans/:id for status.
    runOrchestratedScan({ scanId: scan._id, projectDir: workDir }).catch((err) => {
      console.error(`[scan] orchestration error for scan ${scan._id}:`, err.message);
    });

    return res.status(202).json({ scan });
  } catch (err) {
    return next(err);
  }
}

async function getScan(req, res, next) {
  try {
    const scan = await Scan.findOne({ _id: req.params.id, owner: req.userId });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    return res.json({ scan });
  } catch (err) {
    return next(err);
  }
}

async function listScanHistory(req, res, next) {
  try {
    const project = await Project.findOne({ _id: req.params.projectId, owner: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const scans = await Scan.find({ project: project._id })
      .sort({ createdAt: -1 })
      .select('status finalScore riskBand createdAt completedAt durationMs engineStatus');

    return res.json({ scans });
  } catch (err) {
    return next(err);
  }
}

async function downloadReport(req, res, next) {
  try {
    const scan = await Scan.findOne({ _id: req.params.id, owner: req.userId }).populate('project');
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.status !== 'completed') {
      return res.status(400).json({ error: 'Report is only available for completed scans' });
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="securedev-report-${scan._id}.pdf"`);
    generateScanPdf(scan, scan.project).pipe(res);
  } catch (err) {
    return next(err);
  }
}

module.exports = { triggerScan, getScan, listScanHistory, downloadReport };
