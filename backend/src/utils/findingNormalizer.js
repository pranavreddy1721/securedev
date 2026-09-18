/**
 * Normalizes and de-duplicates findings produced by multiple security engines.
 *
 * The same issue can legitimately be reported by more than one engine
 * (for example, a hardcoded secret may be found by both Semgrep and the
 * secret scanner). Counting both reports would artificially increase the
 * scoring penalty, so equivalent findings are merged before scoring.
 */

const SEVERITY_RANK = Object.freeze({
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

function normalizePath(file = '') {
  return String(file).replaceAll('\\', '/').replace(/^\.\//, '').toLowerCase();
}

function normalizeTitle(title = '') {
  return String(title).trim().toLowerCase().replace(/\s+/g, ' ');
}

function findingKey(finding) {
  return [
    finding.category || '',
    normalizePath(finding.file || ''),
    finding.line ?? '',
    normalizeTitle(finding.title || ''),
  ].join('|');
}

function deduplicateFindings(findings = []) {
  const merged = new Map();

  for (const finding of findings) {
    const key = findingKey(finding);
    const existing = merged.get(key);

    if (!existing) {
      merged.set(key, {
        ...finding,
        engines: [finding.engine].filter(Boolean),
      });
      continue;
    }

    if (finding.engine && !existing.engines.includes(finding.engine)) {
      existing.engines.push(finding.engine);
    }

    // Preserve the strongest severity when engines disagree.
    if ((SEVERITY_RANK[finding.severity] || 0) > (SEVERITY_RANK[existing.severity] || 0)) {
      existing.severity = finding.severity;
    }

    // Prefer a concrete location/description when the first engine omitted it.
    if (!existing.file && finding.file) existing.file = finding.file;
    if (!existing.line && finding.line) existing.line = finding.line;
    if (!existing.description && finding.description) existing.description = finding.description;
    if (!existing.owaspRef && finding.owaspRef) existing.owaspRef = finding.owaspRef;
    existing.heuristic = Boolean(existing.heuristic && finding.heuristic);
  }

  return Array.from(merged.values()).map(({ engines, ...finding }) => ({
    ...finding,
    // Keep the original schema compatible while retaining provenance.
    engine: finding.engine,
    engines,
  }));
}

module.exports = { deduplicateFindings, findingKey };
