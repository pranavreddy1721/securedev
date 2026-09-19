/**
 * Regex-based secret detection patterns.
 * Keep patterns specific enough to reduce false positives. This engine is
 * intentionally heuristic; findings should be reviewed before remediation.
 */

module.exports = [
  {
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
  },
  {
    name: 'AWS Secret Access Key (assignment)',
    regex: /(?:aws[_-]?(?:secret|access)[_-]?key|aws_secret_access_key)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/gi,
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
    regex: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9\-_]{16,}['"]/gi,
    severity: 'high',
  },
  {
    name: 'Private Key block (RSA/EC/PGP/OpenSSH/DSA)',
    regex: /-----BEGIN (?:RSA|EC|PGP|OPENSSH|DSA|PRIVATE) PRIVATE KEY-----/g,
    severity: 'critical',
  },
  {
    name: 'Slack Token',
    regex: /xox[baprs]-[0-9A-Za-z-]{10,}/g,
    severity: 'high',
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /gh[pousr]_[A-Za-z0-9]{20,}/g,
    severity: 'critical',
  },
  {
    name: 'Stripe API Key',
    regex: /sk_(?:live|test)_[0-9a-zA-Z]{20,}/g,
    severity: 'critical',
  },
  {
    name: 'Google OAuth Client Secret',
    regex: /(?:client_secret|google_client_secret)\s*[:=]\s*['"][A-Za-z0-9._\-]{16,}['"]/gi,
    severity: 'high',
  },
  {
    name: 'Generic private token assignment',
    regex: /(?:access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9._\-+/=]{20,}['"]/gi,
    severity: 'high',
  },
  {
    name: 'Generic password assignment (hardcoded)',
    regex: /(password|passwd|pwd)\s*[:=]\s*['"][^'"\s]{8,}['"]/gi,
    severity: 'medium',
  },
];
