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
const { analyzeFinding } = require('../services/aiSecurity.service');

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
        if (!user?.github?.accessTokenEncrypted) throw new Error('GitHub is not connected for this account');
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
      return res.status(202).json({ scan });
    }

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

async function analyzeFindingWithAi(req, res, next) {
  try {
    const index = Number(req.params.findingIndex);
    if (!Number.isInteger(index) || index < 0) return res.status(400).json({ error: 'Invalid finding index' });

    const scan = await Scan.findOne({ _id: req.params.id, owner: req.userId });
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (scan.status !== 'completed') return res.status(400).json({ error: 'AI analysis is available only for completed scans' });

    const finding = scan.findings[index];
    if (!finding) return res.status(404).json({ error: 'Finding not found' });

    const analysis = await analyzeFinding(finding.toObject ? finding.toObject() : finding);
    return res.json({ analysis });
  } catch (err) {
    if (err.code === 'AI_NOT_CONFIGURED') {
      return res.status(503).json({ error: err.message, code: err.code });
    }

    if (err.code === 'AI_NETWORK_ERROR') {
      return res.status(502).json({
        error: 'SecureDev could not reach the Gemini API. Check Render network access and GEMINI_API_KEY, then try again.',
        code: err.code,
      });
    }

    if (err.code === 'AI_PROVIDER_ERROR') {
      const status = Number(err.statusCode);
      if (status === 400 || status === 401 || status === 403) {
        return res.status(502).json({
          error: 'Gemini rejected the request. Verify that GEMINI_API_KEY is a current Gemini authorization key with Gemini API access, and that GEMINI_MODEL is available to the key.',
          code: err.code,
        });
      }
      if (status === 404) {
        return res.status(502).json({
          error: 'The configured Gemini model or Interactions API endpoint was not found. Check GEMINI_MODEL in Render.',
          code: err.code,
        });
      }
      if (status === 429) {
        return res.status(502).json({
          error: 'Gemini rate limit or quota was reached. Please try again shortly.',
          code: err.code,
        });
      }
      return res.status(502).json({
        error: 'Gemini could not analyze this finding. Check the backend logs for the provider error.',
        code: err.code,
      });
    }

    if (err.code === 'AI_EMPTY_RESPONSE' || err.code === 'AI_INVALID_RESPONSE') {
      return res.status(502).json({ error: err.message, code: err.code });
    }

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
    if (scan.status !== 'completed') return res.status(400).json({ error: 'Report is only available for completed scans' });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="securedev-report-${scan._id}.pdf"`);
    generateScanPdf(scan, scan.project).pipe(res);
  } catch (err) {
    return next(err);
  }
}

module.exports = { triggerScan, getScan, analyzeFindingWithAi, listScanHistory, downloadReport };
