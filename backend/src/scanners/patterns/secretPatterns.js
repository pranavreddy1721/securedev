/**
 * Regex-based secret detection patterns.
 * Flagged in the spec as "I'll want to review the regex patterns" — kept in
 * this single file, deliberately separate from scanner logic, so they're
 * easy to audit/tune without touching the scanning code.
 *
 * Each pattern: { name, regex, severity }
 * Regexes should be reasonably specific to avoid excessive false positives
 * (e.g. requiring a minimum key length) — tune as you review.
 */

module.exports = [
  {
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
  },
  {
    name: 'AWS Secret Access Key (assignment)',
    regex: /aws(.{0,20})?(secret|access)?[_-]?key\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi,
    severity: 'critical',
  },
  {
    name: 'MongoDB Connection String with credentials',
    regex: /mongodb(\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s'"]+/gi,
    severity: 'critical',
  },
  {
    name: 'Generic JWT Secret assignment',
    regex: /jwt[_-]?secret\s*[:=]\s*['"][^'"\s]{8,}['"]/gi,
    severity: 'high',
  },
  {
    name: 'Firebase API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'high',
  },
  {
    name: 'Generic API Key assignment',
    regex: /api[_-]?key\s*[:=]\s*['"][A-Za-z0-9\-_]{16,}['"]/gi,
    severity: 'high',
  },
  {
    name: 'Private Key block (RSA/EC/PGP/OpenSSH)',
    regex: /-----BEGIN (RSA|EC|PGP|OPENSSH|DSA) PRIVATE KEY-----/g,
    severity: 'critical',
  },
  {
    name: 'Slack Token',
    regex: /xox[baprs]-[0-9A-Za-z-]{10,}/g,
    severity: 'high',
  },
  {
    name: 'Generic password assignment (hardcoded)',
    regex: /(password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{6,}['"]/gi,
    severity: 'medium',
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /ghp_[A-Za-z0-9]{36}/g,
    severity: 'critical',
  },
  {
    name: 'Stripe API Key',
    regex: /sk_(live|test)_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
  },
];
