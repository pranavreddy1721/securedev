const mongoose = require('mongoose');

const findingSchema = new mongoose.Schema(
  {
    category: {
      type: String,
      required: true,
      enum: [
        'vulnerableDependencies',
        'hardcodedSecrets',
        'injectionFlaws',
        'xss',
        'brokenAuthentication',
        'securityMisconfiguration',
        'insecureFileUploads',
        'brokenAccessControl',
        'sensitiveDataExposure',
      ],
    },
    severity: { type: String, required: true, enum: ['critical', 'high', 'medium', 'low'] },
    title: { type: String, required: true },
    description: { type: String, default: '' },
    file: { type: String, default: null },
    line: { type: Number, default: null },
    engine: { type: String, required: true, enum: ['npm-audit', 'secret-scanner', 'semgrep', 'heuristic'] },
    owaspRef: { type: String, default: null },
    heuristic: { type: Boolean, default: false }, // true for the 3 pattern-based-only categories
  },
  { _id: false }
);

const subScoreSchema = new mongoose.Schema(
  {
    dependency: { type: Number, required: true },
    authentication: { type: Number, required: true },
    secrets: { type: Number, required: true },
    owaspCompliance: { type: Number, required: true },
    configuration: { type: Number, required: true },
  },
  { _id: false }
);

const scanSchema = new mongoose.Schema(
  {
    project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },

    status: {
      type: String,
      enum: ['queued', 'running', 'completed', 'failed'],
      default: 'queued',
    },
    error: { type: String, default: null },

    // Per-engine execution status — lets a partial failure (e.g. Semgrep timing out)
    // still produce a usable report instead of failing the whole scan.
    engineStatus: {
      npmAudit: { type: String, enum: ['pending', 'success', 'failed', 'skipped'], default: 'pending' },
      secretScanner: { type: String, enum: ['pending', 'success', 'failed', 'skipped'], default: 'pending' },
      semgrep: { type: String, enum: ['pending', 'success', 'failed', 'skipped'], default: 'pending' },
    },

    findings: { type: [findingSchema], default: [] },
    subScores: { type: subScoreSchema, default: null },
    finalScore: { type: Number, default: null },
    riskBand: { type: String, default: null },

    startedAt: { type: Date, default: null },
    completedAt: { type: Date, default: null },
    durationMs: { type: Number, default: null },
  },
  { timestamps: true }
);

scanSchema.index({ project: 1, createdAt: -1 });

module.exports = mongoose.model('Scan', scanSchema);
