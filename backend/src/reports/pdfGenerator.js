const PDFDocument = require('pdfkit');

const PAGE = {
  left: 48,
  right: 48,
  top: 48,
  contentBottom: 730,
  footerLine: 758,
  width: 499,
};

const C = {
  ink: '#0f172a', text: '#334155', muted: '#64748b', border: '#dbe3ec',
  accent: '#10b981', accentDark: '#047857', soft: '#f8fafc', blue: '#eff6ff',
  blueText: '#1d4ed8', green: '#ecfdf5', greenText: '#166534',
  amber: '#fffbeb', amberText: '#92400e', white: '#ffffff',
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV = {
  critical: ['#dc2626', '#fee2e2'],
  high: ['#ea580c', '#ffedd5'],
  medium: ['#d97706', '#fef3c7'],
  low: ['#65a30d', '#ecfccb'],
};

const CATEGORY_LABELS = {
  vulnerableDependencies: 'Vulnerable Dependencies', hardcodedSecrets: 'Hardcoded Secrets',
  injectionFlaws: 'Injection Flaws', xss: 'Cross-Site Scripting (XSS)',
  brokenAuthentication: 'Broken Authentication', securityMisconfiguration: 'Security Misconfiguration',
  insecureFileUploads: 'Insecure File Uploads', brokenAccessControl: 'Broken Access Control',
  sensitiveDataExposure: 'Sensitive Data Exposure',
};

const CATEGORY_EXPLANATIONS = {
  vulnerableDependencies: 'A package used by your project has a known security issue. Updating the package can reduce the risk.',
  hardcodedSecrets: 'A password, API key, token, or similar secret appears to be stored in project files instead of outside the source code.',
  injectionFlaws: 'User-controlled input may reach a sensitive operation without enough protection, allowing an attacker to influence what the application does.',
  xss: 'Untrusted content may be displayed in a web page without enough protection, allowing malicious browser code to run for another user.',
  brokenAuthentication: 'The application may have a weakness in the way it verifies users or manages authenticated sessions.',
  securityMisconfiguration: 'A security-sensitive setting appears unsafe or incomplete. A wrong configuration can expose functionality that should be protected.',
  insecureFileUploads: 'Uploaded files may not be checked or stored safely enough. A malicious file could cause unexpected behavior.',
  brokenAccessControl: 'The application may not consistently check whether a user is allowed to access an action or resource.',
  sensitiveDataExposure: 'An API response or other output may reveal information that should remain private, such as tokens, secrets, or password-related data.',
};

const CATEGORY_ACTIONS = {
  vulnerableDependencies: 'Update the affected package to a patched version, review the change, and run the scan again.',
  hardcodedSecrets: 'Remove the secret from source code, rotate the exposed credential, and store future secrets in environment variables or a secret manager.',
  injectionFlaws: 'Validate and constrain user input, use safe APIs or parameterized operations, and add a regression test for the affected path.',
  xss: 'Encode untrusted output for its destination, avoid unsafe HTML insertion, and validate input where appropriate.',
  brokenAuthentication: 'Review login, session, token, and authorization checks around the reported code and add tests for unauthorized access.',
  securityMisconfiguration: 'Review the reported configuration, apply a secure default, and verify the behavior in a production-like environment.',
  insecureFileUploads: 'Restrict file types and sizes, validate uploaded content, store uploads safely, and prevent uploaded files from being executed.',
  brokenAccessControl: 'Add an explicit authorization check before the sensitive operation and test both allowed and denied users.',
  sensitiveDataExposure: 'Return only the fields the client needs and remove secrets, tokens, password hashes, or other private values from responses.',
};

const SUBSCORES = {
  dependency: ['Dependency Security', 'Third-party packages and known vulnerabilities.', 30],
  authentication: ['Authentication', 'Protection around user identity and access.', 20],
  secrets: ['Secrets Detection', 'Credentials or secret-like values in source code.', 20],
  owaspCompliance: ['Application Security', 'Common application security risks found in code.', 20],
  configuration: ['Configuration', 'Security-sensitive application configuration.', 10],
};

async function generateScanPdf(scan, project) {
  const doc = new PDFDocument({
    size: 'A4',
    margins: { top: PAGE.top, bottom: 40, left: PAGE.left, right: PAGE.right },
    info: {
      Title: `SecureDev Security Report - ${project?.name || 'Project'}`,
      Author: 'SecureDev',
      Subject: 'Application security assessment',
    },
  });

  const chunks = [];
  const pdf = new Promise((resolve, reject) => {
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });

  const p = createPages(doc);
  drawCover(p, scan, project);
  p.next('Security overview', 'Score breakdown and security checks used for this assessment.');
  drawOverview(p, scan);
  p.next('Findings and remediation', 'Plain-language explanations of detected issues and practical next steps.');
  drawFindings(p, scan);
  p.next('How SecureDev produced this report', 'A transparent summary of the scanning process, scoring model, and limitations.');
  drawMethodology(p, scan);
  p.finish();
  doc.end();
  return pdf;
}

function createPages(doc) {
  let page = 1;
  let y = PAGE.top;
  let started = false;

  function footer() {
    doc.save();
    doc.strokeColor(C.border).lineWidth(0.6).moveTo(PAGE.left, PAGE.footerLine).lineTo(doc.page.width - PAGE.right, PAGE.footerLine).stroke();
    doc.font('Helvetica').fontSize(7.5).fillColor('#94a3b8').text(`SecureDev Security Report  |  Page ${page}`, PAGE.left, PAGE.footerLine + 8, { width: PAGE.width, align: 'center', lineBreak: false });
    doc.restore();
  }

  function brand() {
    doc.roundedRect(PAGE.left, PAGE.top, 38, 38, 9).fill(C.accent);
    doc.fillColor(C.white).font('Helvetica-Bold').fontSize(21).text('✓', PAGE.left + 10, PAGE.top + 7, { lineBreak: false });
    doc.fillColor(C.ink).font('Helvetica-Bold').fontSize(21).text('Secure', PAGE.left + 50, PAGE.top + 3, { lineBreak: false });
    doc.fillColor(C.accentDark).text('Dev', PAGE.left + 113, PAGE.top + 3, { lineBreak: false });
    doc.font('Helvetica').fontSize(8.5).fillColor(C.muted).text('Application security made easier to understand', PAGE.left + 50, PAGE.top + 27, { lineBreak: false });
  }

  function header(title, subtitle) {
    brand();
    y = PAGE.top + 58;
    y = text(doc, title, PAGE.left, y, PAGE.width, 'Helvetica-Bold', 20, C.ink, 0) + 4;
    y = text(doc, subtitle, PAGE.left, y, PAGE.width, 'Helvetica', 9, C.muted, 2) + 12;
  }

  function next(title, subtitle) {
    if (started) footer();
    doc.addPage();
    page += 1;
    started = true;
    header(title, subtitle);
  }

  function first() {
    started = true;
    brand();
  }

  function ensure(height) {
    if (y + height <= PAGE.contentBottom) return;
    footer();
    doc.addPage();
    page += 1;
    header('Security report continued', 'The report continues below; each finding is kept together on one page.');
  }

  function finish() { if (started) footer(); }

  first();
  return { doc, get y() { return y; }, set y(v) { y = v; }, ensure, next, finish };
}

function drawCover(p, scan, project) {
  const d = p.doc;
  p.y = PAGE.top + 72;
  p.y = text(d, 'Security Assessment Report', PAGE.left, p.y, PAGE.width, 'Helvetica-Bold', 27, C.ink, 0) + 10;
  p.y = text(d, `Project: ${project?.name || 'Unknown project'}`, PAGE.left, p.y, PAGE.width, 'Helvetica', 11, C.muted, 0) + 3;
  p.y = text(d, `Scan completed: ${formatDate(scan.completedAt)}`, PAGE.left, p.y, PAGE.width, 'Helvetica', 10, C.muted, 0) + 2;
  if (scan.durationMs) p.y = text(d, `Scan duration: ${formatDuration(scan.durationMs)}`, PAGE.left, p.y, PAGE.width, 'Helvetica', 10, C.muted, 0) + 10;

  scoreHero(p, scan);
  p.y += 12;
  section(p, 'Executive summary', 'A quick explanation for technical and non-technical readers.');
  infoBox(p, 'What the score means', riskMeaning(scan.riskBand), C.soft, C.text);
  p.y += 8;
  section(p, 'At a glance', 'The most important results from this scan.');
  const findings = scan.findings || [];
  const counts = severityCounts(findings);
  metrics(p, [
    ['Issues found', String(findings.length), 'Total findings detected'],
    ['Critical / High', String(counts.critical + counts.high), 'Needs prompt attention'],
    ['Checks completed', `${successfulEngines(scan)}/3`, 'Security engines finished'],
    ['Assessment', scan.assessmentStatus === 'complete' ? 'Complete' : 'Incomplete', 'Coverage status'],
  ]);
  p.y += 2;
  infoBox(p, scan.assessmentStatus === 'complete' ? 'How to read this report' : 'Important notice',
    scan.assessmentStatus === 'complete'
      ? 'Start with Critical and High findings. Each issue explains what it means, why it matters, where it was found, and what to do next.'
      : 'This assessment is incomplete. The available findings are useful, but the score should not be treated as a complete assessment.',
    scan.assessmentStatus === 'complete' ? C.blue : C.amber,
    scan.assessmentStatus === 'complete' ? C.blueText : C.amberText);
}

function scoreHero(p, scan) {
  const d = p.doc, h = 112;
  p.ensure(h);
  const y = p.y;
  const score = Number.isFinite(Number(scan.finalScore)) ? Number(scan.finalScore).toFixed(1) : 'N/A';
  const risk = scan.riskBand || 'Risk level unavailable';
  d.roundedRect(PAGE.left, y, PAGE.width, h, 12).fill('#f1f5f9');
  d.roundedRect(PAGE.left, y, 7, h, 3).fill(riskColor(risk));
  d.font('Helvetica-Bold').fontSize(9).fillColor(C.muted).text('OVERALL SECURITY SCORE', PAGE.left + 22, y + 16, { lineBreak: false });
  d.font('Helvetica-Bold').fontSize(37).fillColor(C.ink).text(score, PAGE.left + 22, y + 36, { lineBreak: false });
  d.font('Helvetica').fontSize(11).fillColor(C.muted).text('/ 100', PAGE.left + 145, y + 53, { lineBreak: false });
  d.font('Helvetica-Bold').fontSize(17).fillColor(riskColor(risk)).text(risk, PAGE.left + 205, y + 21, { width: 270, lineBreak: false });
  d.font('Helvetica-Bold').fontSize(9).fillColor(C.text).text('Risk level', PAGE.left + 205, y + 47, { lineBreak: false });
  text(d, riskMeaning(risk), PAGE.left + 205, y + 63, 270, 'Helvetica', 8.4, C.text, 2);
  p.y = y + h;
}

function drawOverview(p, scan) {
  section(p, 'How the score is calculated', 'The final score is a weighted summary of five security areas. A lower sub-score means more issues were detected in that area.');
  const sub = scan.subScores || {};
  for (const [key, [label, explanation, weight]] of Object.entries(SUBSCORES)) {
    p.ensure(68);
    const y = p.y, d = p.doc, score = Number.isFinite(Number(sub[key])) ? Math.round(Number(sub[key])) : null;
    d.roundedRect(PAGE.left, y, PAGE.width, 68, 9).fill(C.white).stroke(C.border);
    text(d, label, PAGE.left + 12, y + 9, 330, 'Helvetica-Bold', 10.5, C.ink, 0);
    text(d, `${weight}% weight`, PAGE.left + 392, y + 9, 88, 'Helvetica-Bold', 7.5, C.muted, 0, 'right');
    text(d, explanation, PAGE.left + 12, y + 27, 350, 'Helvetica', 7.8, C.muted, 1.5);
    text(d, score === null ? 'N/A' : `${score}/100`, PAGE.left + 420, y + 27, 60, 'Helvetica-Bold', 9.5, C.text, 0, 'right');
    d.roundedRect(PAGE.left + 12, y + 50, PAGE.width - 100, 6, 3).fill('#e2e8f0');
    if (score !== null) d.roundedRect(PAGE.left + 12, y + 50, (PAGE.width - 100) * clamp(score, 0, 100) / 100, 6, 3).fill(scoreBarColor(score));
    p.y = y + 77;
  }
  infoBox(p, 'How to interpret this section', 'The percentage beside each area is its contribution to the final score. Dependency Security has a 30% weight, so dependency findings can have a substantial effect on the overall result.', C.blue, C.blueText);
  section(p, 'Security checks performed', 'These checks work together to give you one report instead of separate scanner outputs.');
  const engines = [
    ['npm audit', scan.engineStatus?.npmAudit, 'Checks third-party packages for publicly known vulnerabilities.'],
    ['Secret scanner', scan.engineStatus?.secretScanner, 'Looks for credentials and other secret-like values in project files.'],
    ['Semgrep', scan.engineStatus?.semgrep, 'Checks source code for security-risk patterns.'],
  ];
  for (const [name, status, explanation] of engines) {
    p.ensure(58);
    const y = p.y, d = p.doc;
    const ok = status === 'success';
    d.roundedRect(PAGE.left, y, PAGE.width, 58, 8).fill(C.white).stroke(C.border);
    text(d, name, PAGE.left + 12, y + 9, 250, 'Helvetica-Bold', 10, C.ink, 0);
    text(d, ok ? 'Completed' : status === 'skipped' ? 'Skipped' : 'Failed', PAGE.left + 390, y + 9, 90, 'Helvetica-Bold', 8, ok ? C.greenText : status === 'skipped' ? C.muted : '#b91c1c', 0, 'right');
    text(d, explanation, PAGE.left + 12, y + 28, PAGE.width - 24, 'Helvetica', 7.8, C.muted, 1.5);
    p.y = y + 66;
  }
}

function drawFindings(p, scan) {
  const findings = [...(scan.findings || [])].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));
  if (!findings.length) {
    infoBox(p, 'No findings detected', 'The completed scanners did not report an issue. This does not guarantee that the application is completely secure.', C.green, C.greenText);
    return;
  }
  const grouped = {};
  findings.forEach(f => { const k = f.category || 'other'; (grouped[k] ||= []).push(f); });
  for (const [category, list] of Object.entries(grouped)) {
    const label = CATEGORY_LABELS[category] || humanize(category);
    const explanation = CATEGORY_EXPLANATIONS[category] || 'A security-related issue was detected in this area.';
    p.ensure(55);
    p.y = text(p.doc, label, PAGE.left, p.y, PAGE.width, 'Helvetica-Bold', 14, C.ink, 0) + 3;
    p.y = text(p.doc, explanation, PAGE.left, p.y, PAGE.width, 'Helvetica', 8.5, C.muted, 2) + 9;
    for (const finding of list) { findingCard(p, finding, category); p.y += 9; }
  }
}

function findingCard(p, finding, category) {
  const d = p.doc;
  const severity = String(finding.severity || 'medium').toLowerCase();
  const [sevColor, sevBg] = SEV[severity] || SEV.medium;
  const title = finding.title || 'Security finding';
  const description = finding.description || 'No detailed description was provided by the scanner.';
  const file = finding.file ? `${finding.file}${finding.line ? ` • Line ${finding.line}` : ''}` : 'Location not provided';
  const why = whyItMatters(severity);
  const action = finding.remediation || CATEGORY_ACTIONS[category] || 'Review the affected code, apply the recommended security control, and run the scan again.';
  const w = PAGE.width - 28;
  const dh = height(d, description, w, 8.3, 2), fh = height(d, file, w, 7.6, 1.5), wh = height(d, why, w, 8.1, 2), ah = height(d, action, w, 8.1, 2);
  const h = 66 + dh + fh + wh + ah + 38;
  p.ensure(h);
  const y = p.y;
  d.roundedRect(PAGE.left, y, PAGE.width, h, 10).fill(C.white).stroke(C.border);
  d.roundedRect(PAGE.left, y, 6, h, 3).fill(sevColor);
  d.roundedRect(PAGE.left + 14, y + 12, 54, 18, 8).fill(sevBg);
  text(d, severity.toUpperCase(), PAGE.left + 14, y + 17, 54, 'Helvetica-Bold', 7, sevColor, 0, 'center');
  text(d, title, PAGE.left + 78, y + 13, PAGE.width - 92, 'Helvetica-Bold', 10.5, C.ink, 1.5);
  let cy = y + 45;
  cy = field(d, 'WHAT WAS FOUND', description, cy, w, 8.3);
  cy = field(d, 'WHERE', file, cy + 7, w, 7.6);
  cy = field(d, 'WHY IT MATTERS', why, cy + 7, w, 8.1);
  field(d, 'WHAT TO DO', action, cy + 7, w, 8.1);
  p.y = y + h;
}

function drawMethodology(p, scan) {
  section(p, 'What SecureDev scanned', 'SecureDev combines several focused checks into one assessment.');
  const steps = [
    ['1. Dependencies', 'npm audit checks project packages against known vulnerability advisories.'],
    ['2. Secrets', 'The secret scanner searches project files for credential-like values that should not be committed.'],
    ['3. Source code', 'Semgrep applies security rules to source code to identify potentially unsafe patterns.'],
    ['4. Heuristics', 'Additional lightweight checks look for common application-security risks such as unsafe uploads, access-control gaps, and sensitive response fields.'],
    ['5. Normalization', 'Duplicate detections are combined so the same underlying issue is not counted repeatedly.'],
    ['6. Scoring', 'Five weighted security areas are combined into the final score.'],
  ];
  for (const [title, body] of steps) {
    const h = 25 + height(p.doc, body, PAGE.width - 28, 8.5, 2);
    p.ensure(h + 8);
    const y = p.y;
    p.doc.roundedRect(PAGE.left, y, PAGE.width, h, 8).fill(C.white).stroke(C.border);
    text(p.doc, title, PAGE.left + 14, y + 8, PAGE.width - 28, 'Helvetica-Bold', 9.5, C.ink, 0);
    text(p.doc, body, PAGE.left + 14, y + 24, PAGE.width - 28, 'Helvetica', 8.5, C.text, 2);
    p.y = y + h + 8;
  }
  section(p, 'Assessment limitations', 'What this report can and cannot tell you.');
  infoBox(p, 'Important', scan.assessmentStatus === 'complete'
    ? 'A completed scan means the configured checks finished successfully. It does not prove that the application is free of vulnerabilities. Pattern-based and dependency checks can miss issues that require business context or manual review.'
    : 'This assessment is incomplete. Findings can still be useful, but the overall score should not be treated as a complete representation of the application security posture.', C.amber, C.amberText);
}

function section(p, title, subtitle) {
  const h = height(p.doc, subtitle, PAGE.width, 8.8, 2) + 28;
  p.ensure(h);
  p.y = text(p.doc, title, PAGE.left, p.y, PAGE.width, 'Helvetica-Bold', 14, C.ink, 0) + 3;
  p.y = text(p.doc, subtitle, PAGE.left, p.y, PAGE.width, 'Helvetica', 8.8, C.muted, 2) + 10;
}

function infoBox(p, title, body, fill, titleColor) {
  const h = 28 + height(p.doc, body, PAGE.width - 28, 8.5, 2) + 12;
  p.ensure(h);
  const y = p.y, d = p.doc;
  d.roundedRect(PAGE.left, y, PAGE.width, h, 9).fill(fill);
  text(d, title, PAGE.left + 14, y + 10, PAGE.width - 28, 'Helvetica-Bold', 8.3, titleColor, 0);
  text(d, body, PAGE.left + 14, y + 25, PAGE.width - 28, 'Helvetica', 8.5, C.text, 2);
  p.y = y + h;
}

function metrics(p, items) {
  p.ensure(64);
  const d = p.doc, gap = 9, w = (PAGE.width - gap * 3) / 4, y = p.y;
  items.forEach((m, i) => {
    const x = PAGE.left + i * (w + gap);
    d.roundedRect(x, y, w, 64, 8).fill(C.white).stroke(C.border);
    text(d, m[1], x + 9, y + 8, w - 18, 'Helvetica-Bold', 13, C.ink, 0, 'left');
    text(d, m[0], x + 9, y + 28, w - 18, 'Helvetica-Bold', 7.1, C.text, 0);
    text(d, m[2], x + 9, y + 41, w - 18, 'Helvetica', 6.4, C.muted, 1);
  });
  p.y = y + 74;
}

function field(d, label, body, y, width, size) {
  text(d, label, PAGE.left + 14, y, width, 'Helvetica-Bold', 7.1, C.muted, 0);
  const by = y + 11;
  const h = height(d, body, width, size, 2);
  text(d, body, PAGE.left + 14, by, width, 'Helvetica', size, C.text, 2);
  return by + h;
}

function text(d, value, x, y, width, font, size, color, lineGap = 0, align = 'left') {
  d.font(font).fontSize(size).fillColor(color);
  d.text(String(value ?? ''), x, y, { width, lineGap, align });
  return y + height(d, value, width, size, lineGap);
}

function height(d, value, width, size, lineGap = 0) {
  return d.heightOfString(String(value ?? ''), { width, font: d._font ? d._font.name : 'Helvetica', size, lineGap });
}

function severityCounts(findings) {
  return findings.reduce((a, f) => { const s = String(f.severity || 'low').toLowerCase(); a[s] = (a[s] || 0) + 1; return a; }, { critical: 0, high: 0, medium: 0, low: 0 });
}
function successfulEngines(scan) { return Object.values(scan.engineStatus || {}).filter(v => v === 'success').length; }
function riskMeaning(risk) {
  const t = String(risk || '').toLowerCase();
  if (t.includes('low')) return 'Few security concerns were detected by the completed checks. Continue reviewing findings and keep dependencies and security controls up to date.';
  if (t.includes('medium')) return 'The scan found security concerns that should be reviewed and addressed. The score is a summary of the checks that completed.';
  if (t.includes('high')) return 'The scan found important security concerns that should be addressed promptly, especially issues rated Critical or High.';
  if (t.includes('critical')) return 'The scan found serious security concerns that require prompt attention before relying on the affected functionality.';
  return 'Review the findings and scanner coverage before treating this assessment as a complete security picture.';
}
function whyItMatters(s) {
  if (s === 'critical') return 'This finding represents a critical security concern and should be addressed before release when the affected code is reachable.';
  if (s === 'high') return 'This finding represents a significant security concern and should normally be addressed before release when the affected code is reachable.';
  if (s === 'medium') return 'This finding represents a moderate security concern. It should be reviewed and fixed as part of normal security maintenance.';
  return 'This finding is a lower-severity signal. Review it in the context of the affected feature and address it when practical.';
}
function humanize(v) { return String(v || 'Other').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, c => c.toUpperCase()); }
function riskColor(r) { const t = String(r || '').toLowerCase(); if (t.includes('critical')) return '#dc2626'; if (t.includes('high')) return '#ea580c'; if (t.includes('medium')) return '#d97706'; return '#16a34a'; }
function scoreBarColor(s) { if (s >= 80) return '#16a34a'; if (s >= 60) return '#d97706'; if (s >= 40) return '#ea580c'; return '#dc2626'; }
function clamp(v, min, max) { return Math.min(max, Math.max(min, v)); }
function formatDuration(ms) { const s = Math.max(0, Math.round(Number(ms) / 1000)); return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`; }
function formatDate(v) { if (!v) return 'Unavailable'; const d = new Date(v); return Number.isNaN(d.getTime()) ? 'Unavailable' : d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }); }

module.exports = { generateScanPdf };