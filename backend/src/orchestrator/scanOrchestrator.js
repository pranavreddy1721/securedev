const { runNpmAuditScan } = require('../scanners/npmAudit.scanner');
const { runSecretScan } = require('../scanners/secret.scanner');
const { runSemgrepScan } = require('../scanners/semgrep.scanner');
const { runHeuristicScan } = require('../scanners/heuristic.scanner');
const { computeScore } = require('../scoring/scoringEngine');
const { deduplicateFindings } = require('../utils/findingNormalizer');
const Scan = require('../models/Scan');
const Project = require('../models/Project');
const { createTempDir, cleanupTempDir } = require('../utils/tempDir');

/**
 * Orchestrates a full scan against a prepared project directory.
 * Core engines run concurrently, but a failed core engine no longer produces
 * a seemingly complete security score. Findings are normalized and merged
 * before scoring so duplicate reports from different engines do not create
 * an artificial penalty.
 */
async function runOrchestratedScan({ scanId, projectDir }) {
  const scan = await Scan.findById(scanId);
  if (!scan) throw new Error(`Scan ${scanId} not found`);

  scan.status = 'running';
  scan.startedAt = new Date();
  scan.assessmentStatus = 'incomplete';
  await scan.save();

  const startTime = Date.now();

  try {
    const [npmResult, secretResult, semgrepResult, heuristicResult] = await Promise.allSettled([
      runNpmAuditScan(projectDir),
      runSecretScan(projectDir),
      runSemgrepScan(projectDir),
      runHeuristicScan(projectDir),
    ]);

    const rawFindings = [];
    const engineStatus = { npmAudit: 'failed', secretScanner: 'failed', semgrep: 'failed' };

    if (npmResult.status === 'fulfilled') {
      engineStatus.npmAudit = npmResult.value.skipped ? 'skipped' : 'success';
      rawFindings.push(...npmResult.value.findings);
    } else {
      console.error(`[orchestrator] npm audit failed for scan ${scanId}:`, npmResult.reason?.message);
    }

    if (secretResult.status === 'fulfilled') {
      engineStatus.secretScanner = 'success';
      rawFindings.push(...secretResult.value);
    } else {
      console.error(`[orchestrator] secret scan failed for scan ${scanId}:`, secretResult.reason?.message);
    }

    if (semgrepResult.status === 'fulfilled') {
      engineStatus.semgrep = 'success';
      rawFindings.push(...semgrepResult.value.findings);
    } else {
      console.error(`[orchestrator] semgrep failed for scan ${scanId}:`, semgrepResult.reason?.message);
    }

    // Heuristic scanning remains supplementary. Its failure is logged but
    // does not make a scan incomplete because it is not a core external engine.
    if (heuristicResult.status === 'fulfilled') {
      rawFindings.push(...heuristicResult.value);
    } else {
      console.error(`[orchestrator] heuristic scan failed for scan ${scanId}:`, heuristicResult.reason?.message);
    }

    scan.engineStatus = engineStatus;

    // npm audit is legitimately skipped when no root package.json exists.
    // Secret scanning and Semgrep are applicable to all supported source ZIPs.
    const coreEngineFailure =
      engineStatus.secretScanner === 'failed' ||
      engineStatus.semgrep === 'failed' ||
      engineStatus.npmAudit === 'failed';

    const findings = deduplicateFindings(rawFindings);
    scan.findings = findings;

    if (coreEngineFailure) {
      scan.status = 'completed';
      scan.assessmentStatus = 'incomplete';
      scan.error = 'One or more core security engines failed. Findings are available, but no comprehensive security score was generated.';
      scan.subScores = null;
      scan.finalScore = null;
      scan.riskBand = null;
      scan.completedAt = new Date();
      scan.durationMs = Date.now() - startTime;
      await scan.save();
      return scan;
    }

    const { subScores, finalScore, riskBand } = computeScore(findings);

    scan.subScores = subScores;
    scan.finalScore = finalScore;
    scan.riskBand = riskBand;
    scan.assessmentStatus = 'complete';
    scan.error = null;
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
    scan.assessmentStatus = 'incomplete';
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
