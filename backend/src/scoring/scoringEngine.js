const {
  CATEGORY_WEIGHTS,
  SEVERITY_POINTS,
  DIMINISHING_RETURNS_K,
  CATEGORY_TO_SUBSCORE,
  getSeverityBand,
} = require('../config/scoring.config');

/**
 * Computes the raw penalty for a set of findings within one sub-score bucket:
 *   rawPenalty = Σ (severityPoints × count)
 */
function computeRawPenalty(findings) {
  return findings.reduce((sum, f) => sum + (SEVERITY_POINTS[f.severity] || 0), 0);
}

/**
 * Diminishing-returns transform: subScore = 100 * exp(-rawPenalty / k)
 * A clean category (no findings) scores 100. Each additional point of
 * severity-weighted penalty reduces the score with decreasing marginal
 * impact — the 1st Critical hurts far more than the 10th.
 */
function applyDiminishingReturns(rawPenalty, k) {
  const score = 100 * Math.exp(-rawPenalty / k);
  return Math.round(score * 100) / 100; // 2 decimal places
}

/**
 * Takes the flat findings array from the orchestrator (already tagged with
 * category per finding) and computes:
 *   - 5 sub-scores (dependency, authentication, secrets, owaspCompliance, configuration)
 *   - the final weighted score
 *   - the risk band label
 *
 * This is the exact implementation of Section 4's formula plus the
 * confirmed hybrid severity-weighted / diminishing-returns sub-score model.
 */
function computeScore(findings) {
  // Group findings by which sub-score bucket they roll up into.
  const bySubScore = {
    dependency: [],
    authentication: [],
    secrets: [],
    owaspCompliance: [],
    configuration: [],
  };

  for (const f of findings) {
    const bucket = CATEGORY_TO_SUBSCORE[f.category];
    if (bucket && bySubScore[bucket]) {
      bySubScore[bucket].push(f);
    }
  }

  const subScores = {};
  for (const bucket of Object.keys(bySubScore)) {
    const rawPenalty = computeRawPenalty(bySubScore[bucket]);
    subScores[bucket] = applyDiminishingReturns(rawPenalty, DIMINISHING_RETURNS_K[bucket]);
  }

  const finalScoreRaw = Object.entries(CATEGORY_WEIGHTS).reduce(
    (sum, [bucket, weight]) => sum + subScores[bucket] * weight,
    0
  );
  const finalScore = Math.round(finalScoreRaw * 100) / 100;

  return {
    subScores,
    finalScore,
    riskBand: getSeverityBand(finalScore),
  };
}

module.exports = { computeScore, computeRawPenalty, applyDiminishingReturns };
