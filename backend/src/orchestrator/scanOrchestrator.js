const { runNpmAuditScan } = require('../scanners/npmAudit.scanner');
const { runSecretScan } = require('../scanners/secret.scanner');
const { runSemgrepScan } = require('../scanners/semgrep.scanner');
const { runHeuristicScan } = require('../scanners/heuristic.scanner');
const { computeScore } = require('../scoring/scoringEngine');
const Scan = require('../models/Scan');
const Project = require('../models/Project');
const { createTempDir, cleanupTempDir } = require('../utils/tempDir');

/**
 * Orchestrates a full scan against a prepared project directory.
 * Per the confirmed decision: npm audit and Semgrep run via child_process
 * (execFile), the secret scanner and heuristic scanner run as plain async
 * JS — all three scan types run concurrently via Promise.allSettled, so one
 * engine failing (e.g. Semgrep timeout) doesn't kill the whole scan.
 *
 * projectDir is always inside os.tmpdir() and is deleted in the finally
 * block regardless of success/failure — no persistent storage of source
 * code, per the confirmed "local temp dir, no S3 in v1" decision.
 */
async function runOrchestratedScan({ scanId, projectDir }) {
  const scan = await Scan.findById(scanId);
  if (!scan) throw new Error(`Scan ${scanId} not found`);

  scan.status = 'running';
  scan.startedAt = new Date();
  await scan.save();

  const startTime = Date.now();

  try {
    const [npmResult, secretResult, semgrepResult, heuristicResult] = await Promise.allSettled([
      runNpmAuditScan(projectDir),
      runSecretScan(projectDir),
      runSemgrepScan(projectDir),
      runHeuristicScan(projectDir),
    ]);

    const findings = [];
    const engineStatus = { npmAudit: 'failed', secretScanner: 'failed', semgrep: 'failed' };

    if (npmResult.status === 'fulfilled') {
      engineStatus.npmAudit = npmResult.value.skipped ? 'skipped' : 'success';
      findings.push(...npmResult.value.findings);
    } else {
      console.error(`[orchestrator] npm audit failed for scan ${scanId}:`, npmResult.reason?.message);
    }

    if (secretResult.status === 'fulfilled') {
      engineStatus.secretScanner = 'success';
      findings.push(...secretResult.value);
    } else {
      console.error(`[orchestrator] secret scan failed for scan ${scanId}:`, secretResult.reason?.message);
    }

    if (semgrepResult.status === 'fulfilled') {
      engineStatus.semgrep = 'success';
      findings.push(...semgrepResult.value.findings);
    } else {
      console.error(`[orchestrator] semgrep failed for scan ${scanId}:`, semgrepResult.reason?.message);
    }

    // Heuristic scan is treated as best-effort/supplementary — its failure
    // doesn't get its own engineStatus slot since it's not one of the 3
    // named engines in the spec, but findings still merge in on success.
    if (heuristicResult.status === 'fulfilled') {
      findings.push(...heuristicResult.value);
    } else {
      console.error(`[orchestrator] heuristic scan failed for scan ${scanId}:`, heuristicResult.reason?.message);
    }

    // If every real engine failed, this scan didn't actually accomplish anything —
    // surface it as failed rather than reporting a misleadingly clean 100 score.
    const allCoreEnginesFailed =
      engineStatus.npmAudit === 'failed' &&
      engineStatus.secretScanner === 'failed' &&
      engineStatus.semgrep === 'failed';

    if (allCoreEnginesFailed) {
      scan.status = 'failed';
      scan.error = 'All scan engines failed to run. See server logs for details.';
      scan.engineStatus = engineStatus;
      scan.completedAt = new Date();
      scan.durationMs = Date.now() - startTime;
      await scan.save();
      return scan;
    }

    const { subScores, finalScore, riskBand } = computeScore(findings);

    scan.findings = findings;
    scan.subScores = subScores;
    scan.finalScore = finalScore;
    scan.riskBand = riskBand;
    scan.engineStatus = engineStatus;
    scan.status = 'completed';
    scan.completedAt = new Date();
    scan.durationMs = Date.now() - startTime;
    await scan.save();

    await Project.findByIdAndUpdate(scan.project, {
      lastScanId: scan._id,
      lastScore: finalScore,
      lastScannedAt: scan.completedAt,
    });

    return scan;
  } catch (err) {
    scan.status = 'failed';
    scan.error = err.message;
    scan.completedAt = new Date();
    scan.durationMs = Date.now() - startTime;
    await scan.save();
    throw err;
  } finally {
    await cleanupTempDir(projectDir).catch((e) =>
      console.error(`[orchestrator] failed to clean up temp dir ${projectDir}:`, e.message)
    );
  }
}

module.exports = { runOrchestratedScan, createTempDir };
