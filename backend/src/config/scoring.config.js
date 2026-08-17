/**
 * Single source of truth for the Unified Security Scoring Model.
 * Referenced by scoringEngine.js and safe to cite directly in the research paper —
 * do not duplicate these numbers anywhere else in the codebase.
 */

// Top-level weighted formula (Section 4 of the spec):
// Security Score = 0.30(Dependency) + 0.20(Authentication) + 0.20(Secrets)
//                 + 0.20(OWASP Compliance) + 0.10(Configuration)
const CATEGORY_WEIGHTS = Object.freeze({
  dependency: 0.30,
  authentication: 0.20,
  secrets: 0.20,
  owaspCompliance: 0.20,
  configuration: 0.10,
});

// Sanity check at load time — weights must sum to 1.0
const weightSum = Object.values(CATEGORY_WEIGHTS).reduce((a, b) => a + b, 0);
if (Math.abs(weightSum - 1) > 1e-9) {
  throw new Error(`CATEGORY_WEIGHTS must sum to 1.0, got ${weightSum}`);
}

// Severity point values used to compute the "raw penalty" per category
// before the diminishing-returns transform is applied.
const SEVERITY_POINTS = Object.freeze({
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
});

// Diminishing-returns constant per sub-score category.
// Formula: subScore = 100 * exp(-rawPenalty / k)
// A single Critical finding (10 points) with k=15 drops a sub-score to
// 100 * e^(-10/15) ≈ 51.3 — tune k per category if empirical data suggests otherwise.
// Keep k identical across categories for now (k=15) so the model has one
// tunable knob to defend, per the confirmed decision. Adjust here, not inline.
const DIMINISHING_RETURNS_K = Object.freeze({
  dependency: 15,
  authentication: 15,
  secrets: 15,
  owaspCompliance: 15,
  configuration: 15,
});

const SEVERITY_BANDS = Object.freeze([
  { min: 80, max: 100, label: 'Low Risk' },
  { min: 60, max: 79, label: 'Medium Risk' },
  { min: 40, max: 59, label: 'High Risk' },
  { min: 0, max: 39, label: 'Critical Risk' },
]);

// Maps each of the 9 spec categories (Section 3) onto which sub-score bucket
// it rolls up into for the weighted formula (Section 4).
const CATEGORY_TO_SUBSCORE = Object.freeze({
  vulnerableDependencies: 'dependency',
  hardcodedSecrets: 'secrets',
  injectionFlaws: 'owaspCompliance',
  xss: 'owaspCompliance',
  brokenAuthentication: 'authentication',
  securityMisconfiguration: 'configuration',
  insecureFileUploads: 'owaspCompliance',
  brokenAccessControl: 'owaspCompliance',
  sensitiveDataExposure: 'owaspCompliance',
});

// Which of the 9 categories are heuristic (pattern-based, not exhaustive)
// in v1 — surfaced in the UI/report as a stated limitation, not hidden.
const HEURISTIC_CATEGORIES = Object.freeze([
  'insecureFileUploads',
  'brokenAccessControl',
  'sensitiveDataExposure',
]);

function getSeverityBand(score) {
  const band = SEVERITY_BANDS.find((b) => score >= b.min && score <= b.max);
  return band ? band.label : 'Unknown';
}

module.exports = {
  CATEGORY_WEIGHTS,
  SEVERITY_POINTS,
  DIMINISHING_RETURNS_K,
  SEVERITY_BANDS,
  CATEGORY_TO_SUBSCORE,
  HEURISTIC_CATEGORIES,
  getSeverityBand,
};
