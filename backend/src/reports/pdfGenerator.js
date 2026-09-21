const PDFDocument = require('pdfkit');
const { HEURISTIC_CATEGORIES } = require('../config/scoring.config');

const PAGE = { left: 50, right: 50, top: 50, bottom: 48, width: 495 };
const SEVERITY_COLORS = {
  critical: '#b91c1c',
  high: '#ea580c',
  medium: '#d97706',
  low: '#65a30d',
};
const SEVERITY_BG = {
  critical: '#fee2e2',
  high: '#ffedd5',
  medium: '#fef3c7',
  low: '#ecfccb',
};

const CATEGORY_LABELS = {
  vulnerableDependencies: 'Vulnerable Dependencies',
  hardcodedSecrets: 'Hardcoded Secrets',
  injectionFlaws: 'Injection Flaws',
  xss: 'Cross-Site Scripting (XSS)',
  brokenAuthentication: 'Broken Authentication',
  securityMisconfiguration: 'Security Misconfiguration',
  insecureFileUploads: 'Insecure File Uploads',
  brokenAccessControl: 'Broken Access Control',
  sensitiveDataExposure: 'Sensitive Data Exposure',
};

const CATEGORY_EXPLANATIONS = {
  vulnerableDependencies: 'A third-party package used by the project has a known security issue. Updating or replacing the package can reduce the risk.',
  hardcodedSecrets: 'A password, API key, token, or other secret appears to be stored directly in the project files. Secrets should be kept outside source code.',
  injectionFlaws: 'User-controlled input may reach a sensitive operation without enough validation. An attacker could potentially change what the application executes.',
  xss: 'Untrusted content may be displayed in a web page without enough protection. This can allow malicious browser code to run for another user.',
  brokenAuthentication: 'The way the application verifies users may contain a weakness. This can increase the risk of unauthorized account access.',
  securityMisconfiguration: 'A security-related setting appears unsafe or incomplete. Incorrect configuration can expose functionality that should be protected.',
  insecureFileUploads: 'Uploaded files may not be checked or stored safely enough. A malicious file could cause unexpected behavior if it is accepted or handled incorrectly.',
  brokenAccessControl: 'The application may not consistently check whether a user is allowed to access an action or resource. This can expose data or functionality to the wrong person.',
  sensitiveDataExposure: 'An API response or other application output may reveal information that should remain private, such as secrets, tokens, or password-related data.',
};

const CATEGORY_ACTIONS = {
  vulnerableDependencies: 'Review the affected package, update it to a patched version, and run the scan again.',
  hardcodedSecrets: 'Remove the secret from source code, rotate the exposed credential, and store future secrets in environment variables or a secret manager.',
  injectionFlaws: 'Validate and constrain user input, use safe APIs or parameterized operations, and add a regression test for the affected path.',
  xss: 'Encode untrusted output for its destination, avoid unsafe HTML insertion, and validate input where appropriate.',
  brokenAuthentication: 'Review login, session, token, and authorization checks around the reported code and add tests for unauthorized access.',
  securityMisconfiguration: 'Review the reported configuration, apply a secure default, and verify the behavior in a production-like environment.',
  insecureFileUploads: 'Restrict file types and sizes, validate uploaded content, store uploads safely, and prevent uploaded files from being executed.',
  brokenAccessControl: 'Add an explicit authorization check before the sensitive operation and test both allowed and denied users.',
  sensitiveDataExposure: 'Return only the fields the client needs and remove secrets, tokens, password hashes, or other private values from responses.',
};

const SUBSCORE_LABELS = {
  dependency: ['Dependency Security', 'Third-party packages and their known security issues.', 30],
  authentication: ['Authentication', 'Protection around user identity and access.', 20],
  secrets: ['Secrets Detection', 'Checks for credentials or secrets committed to source code.', 20],
  owaspCompliance: ['Application Security', 'Security findings mapped to common application-risk categories.', 20],
  configuration: ['Configuration', 'Security-sensitive application configuration checks.', 10],
};

function generateScanPdf(scan, project) {
  const doc = new PDFDocument({ size: 'A4', margins: { top: PAGE.top, bottom: PAGE.bottom, left: PAGE.left, right: PAGE.right }, bufferPages: true });

  addFooter(doc);
  drawHeader(doc, project, scan);
  drawExecutiveSummary(doc, scan);
  drawKeyMetrics(doc, scan);
  drawScoreBreakdown(doc, scan);
  drawEngineCoverage(doc, scan);
  drawFindings(doc, scan);
  drawMethodology(doc, scan);

  // Add page numbers after the document has been laid out.
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i += 1) {
    doc.switchToPage(i);
    doc.save();
    doc.fontSize(8).fillColor('#94a3b8').text(`SecureDev Security Report  •  Page ${i + 1} of ${range.count}`, PAGE.left, doc.page.height - 30, { width: PAGE.width, align: 'center' });
    doc.restore();
  }

  doc.end();
  return doc;
}

function addFooter(doc) {
  doc.on('pageAdded', () => {
    doc.save();
    doc.strokeColor('#e2e8f0').lineWidth(0.5).moveTo(PAGE.left, doc.page.height - 42).lineTo(doc.page.width - PAGE.right, doc.page.height - 42).stroke();
    doc.restore();
  });
}

function drawHeader(doc, project, scan) {
  doc.roundedRect(PAGE.left, doc.y, 42, 42, 10).fill('#10b981');
  doc.fillColor('#ffffff').fontSize(22).font('Helvetica-Bold').text('✓', PAGE.left + 11, doc.y - 34);
  doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(22).text('SecureDev', PAGE.left + 54, doc.y - 38);
  doc.font('Helvetica').fontSize(9).fillColor('#64748b').text('Security assessment report', PAGE.left + 55, doc.y - 18);
  doc.moveTo(PAGE.left, 112).lineTo(doc.page.width - PAGE.right, 112).strokeColor('#dbeafe').lineWidth(1).stroke();
  doc.y = 132;

  doc.font('Helvetica-Bold').fontSize(24).fillColor('#0f172a').text('Security Report');
  doc.moveDown(0.3);
  doc.font('Helvetica').fontSize(11).fillColor('#475569').text(`Project: ${project?.name || 'Unknown project'}`);
  doc.text(`Scan completed: ${scan.completedAt ? new Date(scan.completedAt).toLocaleString() : 'N/A'}`);
  if (scan.durationMs) doc.text(`Scan duration: ${formatDuration(scan.durationMs)}`);
  doc.moveDown(1);
}

function drawExecutiveSummary(doc, scan) {
  const score = Number.isFinite(scan.finalScore) ? Number(scan.finalScore).toFixed(1) : 'N/A';
  const risk = scan.riskBand || 'Unknown Risk';
  const meaning = riskMeaning(risk);
  const y = doc.y;
  const h = 122;

  doc.roundedRect(PAGE.left, y, PAGE.width, h, 12).fill('#f8fafc');
  doc.roundedRect(PAGE.left, y, 8, h, 4).fill(riskColor(risk));

  doc.font('Helvetica-Bold').fontSize(10).fillColor('#64748b').text('OVERALL SECURITY SCORE', PAGE.left + 24, y + 18);
  doc.font('Helvetica-Bold').fontSize(42).fillColor('#0f172a').text(score, PAGE.left + 24, y + 38, { width: 120 });
  doc.font('Helvetica').fontSize(11).fillColor('#64748b').text('/ 100', PAGE.left + 112, y + 63);

  doc.font('Helvetica-Bold').fontSize(18).fillColor(riskColor(risk)).text(risk, PAGE.left + 190, y + 25);
  doc.font('Helvetica-Bold').fontSize(10).fillColor('#334155').text('What this means', PAGE.left + 190, y + 54);
  doc.font('Helvetica').fontSize(9.5).fillColor('#475569').text(meaning, PAGE.left + 190, y + 70, { width: 275, lineGap: 2 });
  doc.y = y + h + 18;
}

function drawKeyMetrics(doc, scan) {
  ensureSpace(doc, 86);
  const findings = scan.findings || [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => { if (counts[f.severity] !== undefined) counts[f.severity] += 1; });
  const successful = Object.values(scan.engineStatus || {}).filter((s) => s === 'success').length;
  const metrics = [
    ['Issues found', String(findings.length), 'Total findings detected'],
    ['Critical / High', `${counts.critical + counts.high}`, 'Needs prompt attention'],
    ['Checks completed', `${successful} / 3`, 'Security engines that finished'],
    ['Assessment', scan.assessmentStatus === 'complete' ? 'Complete' : 'Incomplete', 'Whether all core checks finished'],
  ];

  sectionTitle(doc, 'At a glance', 'A simple summary before the detailed findings.');
  const gap = 10;
  const w = (PAGE.width - gap * 3) / 4;
  const y = doc.y;
  metrics.forEach((m, i) => {
    const x = PAGE.left + i * (w + gap);
    doc.roundedRect(x, y, w, 60, 8).fill('#ffffff').stroke('#e2e8f0');
    doc.font('Helvetica-Bold').fontSize(16).fillColor('#0f172a').text(m[1], x + 10, y + 12, { width: w - 20 });
    doc.font('Helvetica-Bold').fontSize(8).fillColor('#334155').text(m[0], x + 10, y + 32, { width: w - 20 });
    doc.font('Helvetica').fontSize(7.5).fillColor('#64748b').text(m[2], x + 10, y + 44, { width: w - 20 });
  });
  doc.y = y + 76;
}

function drawScoreBreakdown(doc, scan) {
  ensureSpace(doc, 170);
  sectionTitle(doc, 'How the score is calculated', 'Each area contributes a different amount to the final 0–100 score.');
  const subScores = scan.subScores || {};
  Object.entries(SUBSCORE_LABELS).forEach(([key, [label, explanation, weight]]) => {
    ensureSpace(doc, 48);
    const score = Number.isFinite(subScores[key]) ? Math.round(subScores[key]) : null;
    const y = doc.y;
    doc.font('Helvetica-Bold').fontSize(9.5).fillColor('#0f172a').text(label, PAGE.left, y);
    doc.font('Helvetica').fontSize(8).fillColor('#64748b').text(`${weight}% weight  •  ${explanation}`, PAGE.left, y + 13, { width: 390 });
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#334155').text(score === null ? 'N/A' : `${score}/100`, PAGE.left + 425, y + 1, { width: 70, align: 'right' });
    const barY = y + 30;
    doc.roundedRect(PAGE.left, barY, PAGE.width, 7, 3).fill('#e2e8f0');
    if (score !== null) doc.roundedRect(PAGE.left, barY, PAGE.width * Math.max(0, Math.min(100, score)) / 100, 7, 3).fill(scoreBarColor(score));
    doc.y = barY + 18;
  });
  doc.moveDown(0.5);
}

function drawEngineCoverage(doc, scan) {
  ensureSpace(doc, 155);
  sectionTitle(doc, 'Security checks performed', 'SecureDev combines three independent checks so the result is easier to review in one place.');
  const engineInfo = [
    ['npm audit', scan.engineStatus?.npmAudit, 'Checks third-party packages for publicly known vulnerabilities.'],
    ['Secret scanner', scan.engineStatus?.secretScanner, 'Looks for credentials and other secret-like values in project files.'],
    ['Semgrep', scan.engineStatus?.semgrep, 'Looks for security-risk patterns in source code.'],
  ];
  engineInfo.forEach(([name, status, explanation]) => {
    ensureSpace(doc, 54);
    const y = doc.y;
    doc.roundedRect(PAGE.left, y, PAGE.width, 45, 7).fill('#f8fafc').stroke('#e2e8f0');
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#0f172a').text(name, PAGE.left + 12, y + 9);
    doc.font('Helvetica').fontSize(8.5).fillColor('#64748b').text(explanation, PAGE.left + 12, y + 24, { width: 360 });
    const color = status === 'success' ? '#15803d' : status === 'skipped' ? '#64748b' : '#b91c1c';
    doc.font('Helvetica-Bold').fontSize(9).fillColor(color).text(humanStatus(status), PAGE.left + 405, y + 17, { width: 78, align: 'right' });
    doc.y = y + 56;
  });
}

function drawFindings(doc, scan) {
  const findings = scan.findings || [];
  sectionTitle(doc, 'Issues found', findings.length ? 'Each issue below explains what it means, why it matters, and what to do next.' : 'No security issues were reported by the completed checks.');

  if (!findings.length) {
    doc.roundedRect(PAGE.left, doc.y, PAGE.width, 62, 8).fill('#ecfdf5').stroke('#bbf7d0');
    doc.font('Helvetica-Bold').fontSize(11).fillColor('#166534').text('No findings detected', PAGE.left + 14, doc.y + 14);
    doc.font('Helvetica').fontSize(9).fillColor('#166534').text('This means the completed scanners did not report an issue. It is not a guarantee that the application is completely secure.', PAGE.left + 14, doc.y + 31, { width: PAGE.width - 28 });
    doc.moveDown(1.2);
    return;
  }

  const byCategory = {};
  findings.forEach((f) => { if (!byCategory[f.category]) byCategory[f.category] = []; byCategory[f.category].push(f); });

  Object.entries(byCategory).forEach(([category, categoryFindings]) => {
    ensureSpace(doc, 90);
    const label = CATEGORY_LABELS[category] || category;
    const isHeuristic = HEURISTIC_CATEGORIES.includes(category);
    doc.roundedRect(PAGE.left, doc.y, PAGE.width, 34, 8).fill('#eff6ff');
    doc.font('Helvetica-Bold').fontSize(11).fillColor('#0f172a').text(label, PAGE.left + 12, doc.y + 10);
    doc.font('Helvetica-Bold').fontSize(8).fillColor('#475569').text(`${categoryFindings.length} issue${categoryFindings.length === 1 ? '' : 's'}`, PAGE.left + 395, doc.y + 11, { width: 88, align: 'right' });
    doc.y += 43;
    doc.font('Helvetica').fontSize(8.5).fillColor('#475569').text(CATEGORY_EXPLANATIONS[category] || 'A security-related issue was detected in this category.', PAGE.left, doc.y, { width: PAGE.width, lineGap: 2 });
    doc.moveDown(0.8);
    if (isHeuristic) {
      doc.roundedRect(PAGE.left, doc.y, PAGE.width, 28, 6).fill('#fffbeb').stroke('#fde68a');
      doc.font('Helvetica-Bold').fontSize(8).fillColor('#92400e').text('Pattern-based check', PAGE.left + 10, doc.y + 8);
      doc.font('Helvetica').fontSize(7.8).fillColor('#92400e').text('This category uses lightweight heuristics and is not exhaustive. Verify the result manually.', PAGE.left + 105, doc.y + 8, { width: PAGE.width - 115 });
      doc.y += 38;
    }

    categoryFindings.forEach((finding) => drawFinding(doc, finding, category));
  });
}

function drawFinding(doc, finding, category) {
  const simple = CATEGORY_EXPLANATIONS[category] || 'A security issue was detected in this area of the project.';
  const action = CATEGORY_ACTIONS[category] || 'Review the reported code, apply the appropriate security fix, and run the scan again.';
  const technical = finding.description || 'The scanner reported an issue but did not provide additional detail.';
  const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : 'Location not provided';
  const detectedBy = (finding.engines && finding.engines.length ? finding.engines : [finding.engine]).filter(Boolean).join(', ');

  const titleHeight = doc.heightOfString(finding.title || 'Untitled finding', { width: 360, font: 'Helvetica-Bold', fontSize: 10 });
  const cardHeight = Math.min(330, Math.max(170, 88 + titleHeight + doc.heightOfString(simple, { width: PAGE.width - 28, font: 'Helvetica', fontSize: 8.5 }) + doc.heightOfString(action, { width: PAGE.width - 28, font: 'Helvetica', fontSize: 8.5 }) + doc.heightOfString(technical, { width: PAGE.width - 28, font: 'Helvetica', fontSize: 8.2 })));
  ensureSpace(doc, Math.min(cardHeight, 300));
  const y = doc.y;

  doc.roundedRect(PAGE.left, y, PAGE.width, cardHeight, 9).fill('#ffffff').stroke('#e2e8f0');
  doc.roundedRect(PAGE.left, y, 5, cardHeight, 3).fill(SEVERITY_COLORS[finding.severity] || '#64748b');

  const pillText = String(finding.severity || 'unknown').toUpperCase();
  doc.roundedRect(PAGE.left + 14, y + 13, 58, 18, 8).fill(SEVERITY_BG[finding.severity] || '#f1f5f9');
  doc.font('Helvetica-Bold').fontSize(7.5).fillColor(SEVERITY_COLORS[finding.severity] || '#475569').text(pillText, PAGE.left + 14, y + 19, { width: 58, align: 'center' });
  doc.font('Helvetica-Bold').fontSize(10).fillColor('#0f172a').text(finding.title || 'Untitled finding', PAGE.left + 84, y + 15, { width: 395 });

  let cursor = y + 47;
  cursor = findingBlock(doc, 'In simple terms', simple, cursor, '#eff6ff', '#1d4ed8');
  cursor = findingBlock(doc, 'Why it matters', severityImpact(finding.severity), cursor, '#f8fafc', '#334155');
  cursor = findingBlock(doc, 'Recommended next step', action, cursor, '#f0fdf4', '#166534');

  doc.font('Helvetica-Bold').fontSize(7.5).fillColor('#64748b').text('Technical detail', PAGE.left + 14, cursor + 2);
  cursor += 13;
  doc.font('Helvetica').fontSize(8.2).fillColor('#475569').text(technical, PAGE.left + 14, cursor, { width: PAGE.width - 28, lineGap: 1.5 });
  cursor += doc.heightOfString(technical, { width: PAGE.width - 28, font: 'Helvetica', fontSize: 8.2, lineGap: 1.5 }) + 8;

  doc.font('Helvetica-Bold').fontSize(7.5).fillColor('#64748b').text('Location', PAGE.left + 14, cursor);
  doc.font('Helvetica').fontSize(7.8).fillColor('#334155').text(location, PAGE.left + 62, cursor, { width: 220 });
  if (detectedBy) {
    doc.font('Helvetica-Bold').fontSize(7.5).fillColor('#64748b').text('Detected by', PAGE.left + 295, cursor);
    doc.font('Helvetica').fontSize(7.8).fillColor('#334155').text(detectedBy, PAGE.left + 355, cursor, { width: 125 });
  }
  if (finding.owaspRef) {
    doc.font('Helvetica-Bold').fontSize(7.5).fillColor('#64748b').text('Reference', PAGE.left + 14, cursor + 13);
    doc.font('Helvetica').fontSize(7.8).fillColor('#334155').text(finding.owaspRef, PAGE.left + 62, cursor + 13, { width: 220 });
  }
  doc.y = y + cardHeight + 12;
}

function findingBlock(doc, title, text, y, background, titleColor) {
  const height = doc.heightOfString(text, { width: PAGE.width - 40, font: 'Helvetica', fontSize: 8.5, lineGap: 1.5 }) + 25;
  doc.roundedRect(PAGE.left + 14, y, PAGE.width - 28, height, 6).fill(background);
  doc.font('Helvetica-Bold').fontSize(7.5).fillColor(titleColor).text(title, PAGE.left + 24, y + 7);
  doc.font('Helvetica').fontSize(8.5).fillColor('#334155').text(text, PAGE.left + 24, y + 19, { width: PAGE.width - 48, lineGap: 1.5 });
  return y + height + 7;
}

function drawMethodology(doc, scan) {
  ensureSpace(doc, 160);
  sectionTitle(doc, 'How SecureDev produced this report', 'The report combines scanner results into one readable assessment.');
  const paragraphs = [
    '1. Project preparation — SecureDev prepares the uploaded project or connected GitHub repository for scanning.',
    '2. Security checks — npm audit checks dependencies, the secret scanner looks for secret-like values, and Semgrep checks source-code patterns.',
    '3. Finding normalization — duplicate detections are merged so the same issue is not counted repeatedly simply because multiple checks reported it.',
    '4. Scoring — findings are converted into category sub-scores and combined using the configured weighted scoring model.',
    '5. Report generation — the findings, score, coverage, limitations, and recommended next steps are presented in this report.',
  ];
  paragraphs.forEach((p) => {
    ensureSpace(doc, 34);
    doc.font('Helvetica').fontSize(9).fillColor('#334155').text(p, PAGE.left, doc.y, { width: PAGE.width, lineGap: 2 });
    doc.moveDown(0.55);
  });

  doc.moveDown(0.4);
  doc.roundedRect(PAGE.left, doc.y, PAGE.width, 58, 8).fill('#f8fafc').stroke('#e2e8f0');
  doc.font('Helvetica-Bold').fontSize(9).fillColor('#0f172a').text('Important limitation', PAGE.left + 12, doc.y + 12);
  doc.font('Helvetica').fontSize(8).fillColor('#475569').text('A clean scan does not prove that an application is completely secure. Pattern-based categories are not exhaustive, and security findings should be reviewed in the context of the application.', PAGE.left + 12, doc.y + 28, { width: PAGE.width - 24, lineGap: 1.5 });
  doc.y += 72;
}

function sectionTitle(doc, title, subtitle) {
  doc.font('Helvetica-Bold').fontSize(15).fillColor('#0f172a').text(title, PAGE.left, doc.y);
  doc.moveDown(0.2);
  doc.font('Helvetica').fontSize(8.5).fillColor('#64748b').text(subtitle, PAGE.left, doc.y, { width: PAGE.width, lineGap: 1.5 });
  doc.moveDown(0.8);
}

function ensureSpace(doc, needed) {
  if (doc.y + needed > doc.page.height - PAGE.bottom - 8) doc.addPage();
}

function riskMeaning(risk) {
  if (risk === 'Low Risk') return 'The scan found relatively few security concerns in the areas checked. Continue reviewing new changes and dependencies as the project evolves.';
  if (risk === 'Medium Risk') return 'The scan found security concerns that should be reviewed and addressed. The score is a summary of the checks that completed.';
  if (risk === 'High Risk') return 'The scan found significant security concerns. Review the highest-severity findings first and rescan after fixes.';
  if (risk === 'Critical Risk') return 'The scan found serious security concerns. Prioritize the critical findings before treating the project as ready for use or release.';
  return 'The scan result could not be assigned a standard risk band.';
}

function severityImpact(severity) {
  if (severity === 'critical') return 'This is the most severe finding level in SecureDev and should be reviewed as a priority because it may represent a serious security exposure.';
  if (severity === 'high') return 'This finding represents a significant security concern and should normally be addressed before release when the affected code is reachable.';
  if (severity === 'medium') return 'This finding represents a moderate security concern. It should be reviewed and fixed as part of normal security maintenance.';
  return 'This finding represents a lower-severity concern, but it can still be useful to fix because several small weaknesses can combine into a larger problem.';
}

function humanStatus(status) {
  if (status === 'success') return 'Completed';
  if (status === 'skipped') return 'Skipped';
  if (status === 'failed') return 'Failed';
  if (status === 'pending') return 'Pending';
  return 'Unknown';
}

function scoreBarColor(score) {
  if (score >= 80) return '#16a34a';
  if (score >= 60) return '#d97706';
  if (score >= 40) return '#ea580c';
  return '#dc2626';
}

function riskColor(band) {
  if (band === 'Low Risk') return '#15803d';
  if (band === 'Medium Risk') return '#b45309';
  if (band === 'High Risk') return '#c2410c';
  if (band === 'Critical Risk') return '#b91c1c';
  return '#334155';
}

function formatDuration(ms) {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return `${minutes}m ${remaining}s`;
}

module.exports = { generateScanPdf };
