const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    name: { type: String, required: true, trim: true, maxlength: 200 },

    source: {
      type: { type: String, enum: ['zip', 'github'], required: true },
      // For github source
      repoFullName: { type: String, default: null }, // e.g. "octocat/hello-world"
      repoUrl: { type: String, default: null },
      defaultBranch: { type: String, default: null },
      // For zip source
      originalFilename: { type: String, default: null },
      sizeBytes: { type: Number, default: null },
    },

    lastScanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', default: null },
    lastScore: { type: Number, default: null },
    lastScannedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

projectSchema.index({ owner: 1, createdAt: -1 });

module.exports = mongoose.model('Project', projectSchema);
