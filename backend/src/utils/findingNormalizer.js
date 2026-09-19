/**
 * Normalize and de-duplicate findings produced by multiple security engines.
 * Equivalent reports are merged before scoring so the same issue is not
 * penalized multiple times simply because more than one engine detected it.
 */
const SEVERITY_RANK = Object.freeze({ low: 1, medium: 2, high: 3, critical: 4 });

function normalizePath(file = '') {
  return String(file).replaceAll('\\', '/').replace(/^\.\//, '').toLowerCase();
}

function normalizeTitle(title = '') {
  return String(title).trim().toLowerCase().replace(/\s+/g, ' ');
}

function findingKey(finding) {
  const category = finding.category || '';
  const file = normalizePath(finding.file || '');
  const title = normalizeTitle(finding.title || '');
  const line = finding.line == null || finding.line === '' ? '' : Number(finding.line);
  return [category, file, line, title].join('|');
}

function deduplicateFindings(findings = []) {
  const merged = new Map();
  for (const finding of findings) {
    const key = findingKey(finding);
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, { ...finding, engines: finding.engine ? [finding.engine] : [] });
      continue;
    }
    if (finding.engine && !existing.engines.includes(finding.engine)) existing.engines.push(finding.engine);
    if ((SEVERITY_RANK[finding.severity] || 0) > (SEVERITY_RANK[existing.severity] || 0)) existing.severity = finding.severity;
    if (!existing.file && finding.file) existing.file = finding.file;
    if (!existing.line && finding.line) existing.line = finding.line;
    if (!existing.description && finding.description) existing.description = finding.description;
    if (!existing.owaspRef && finding.owaspRef) existing.owaspRef = finding.owaspRef;
    existing.heuristic = Boolean(existing.heuristic && finding.heuristic);
  }
  return Array.from(merged.values());
}

module.exports = { deduplicateFindings, findingKey };
