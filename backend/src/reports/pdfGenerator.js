const PDFDocument = require('pdfkit');
const { HEURISTIC_CATEGORIES } = require('../config/scoring.config');

const PAGE = {
  left: 48,
  right: 48,
  top: 52,
  bottom: 62,
  width: 499,
};

const COLORS = {
  ink: '#0f172a',
  text: '#334155',
  muted: '#64748b',
  border: '#e2e8f0',
  accent: '#10b981',
  accentDark: '#047857',
  blueLight: '#eff6ff',
  greenLight: '#ecfdf5',
  amberLight: '#fffbeb',
  redLight: '#fef2f2',
  soft: '#f8fafc',
};

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

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

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
  vulnerableDependencies: 'A package used by your project has a known security issue. Updating the package can reduce the risk.',
  hardcodedSecrets: 'A password, API key, token, or similar secret appears to be stored in project files instead of being kept outside the source code.',
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

const SUBSCORE_INFO = {
  dependency: ['Dependency Security', 'Third-party packages and known vulnerabilities.', 30],
  authentication: ['Authentication', 'Protection around user identity and access.', 20],
  secrets: ['Secrets Detection', 'Credentials or secret-like values in source code.', 20],
  owaspCompliance: ['Application Security', 'Common application security risks found in code.', 20],
  configuration: ['Configuration', 'Security-sensitive application configuration.', 10],
};

function generateScanPdf(scan, project) {
  const doc = new PDFDocument({
    size: 'A4',
    margins: { top: PAGE.top, bottom: PAGE.bottom, left: PAGE.left, right: PAGE.right },
    autoFirstPage: true,
    info: {
      Title: `SecureDev Security Report - ${project?.name || 'Project'}`,
      Author: 'SecureDev',
      Subject: 'Application security assessment',
    },
  });

  let pageNumber = 1;
  doc.on('pageAdded', () => {
    pageNumber += 1;
    drawPageChrome(doc, pageNumber);
  });

  drawPageChrome(doc, pageNumber);
  drawCover(doc, scan, project);

  addContentPage(doc, 'Security overview', 'Score breakdown and security checks used for this assessment.', (d) => {
    drawScoreBreakdown(d, scan);
    drawEngineCoverage(d, scan);
  });

  addContentPage(doc, 'Findings and remediation', 'Plain-language explanations of detected issues and practical next steps.', (d) => {
    drawFindings(d, scan);
  });

  addContentPage(doc, 'How SecureDev produced this report', 'A transparent summary of the scanning process, scoring model, and limitations.', (d) => {
    drawMethodology(d, scan);
  });

  doc.end();
  return doc;
}

function addContentPage(doc, title, subtitle, renderer) {
  doc.addPage();
  drawPageHeader(doc, title, subtitle);
  renderer(doc);
}

function drawPageChrome(doc, pageNumber) {
  const y = doc.page.height - PAGE.bottom + 10;
  doc.save();
  doc.strokeColor(COLORS.border).lineWidth(0.6)
    .moveTo(PAGE.left, y).lineTo(doc.page.width - PAGE.right, y).stroke();
  doc.font('Helvetica').fontSize(7.5).fillColor('#94a3b8')
    .text(`SecureDev Security Report  |  Page ${pageNumber}`, PAGE.left, doc.page.height - 42, {
      width: PAGE.width,
      align: 'center',
      // Footer text is intentionally outside the normal content area. Prevent
      // PDFKit's line wrapper from treating it as a content overflow and
      // calling addPage(), which would recursively fire pageAdded.
      lineBreak: false,
    });
  doc.restore();
}

function drawCover(doc, scan, project) {
  const projectName = project?.name || 'Unknown project';
  const score = Number.isFinite(Number(scan.finalScore)) ? Number(scan.finalScore).toFixed(1) : 'N/A';
  const risk = scan.riskBand || 'Risk level unavailable';
  const findings = scan.findings || [];
  const counts = severityCounts(findings);

  drawBrand(doc, 52);
  doc.y = 112;
  doc.font('Helvetica-Bold').fontSize(28).fillColor(COLORS.ink).text('Security Assessment Report');
  doc.moveDown(0.3);
  doc.font('Helvetica').fontSize(11).fillColor(COLORS.muted)
    .text(`Project: ${projectName}`)
    .text(`Scan completed: ${formatDate(scan.completedAt)}`);
  if (scan.durationMs) doc.text(`Scan duration: ${formatDuration(scan.durationMs)}`);

  doc.moveDown(1.1);
  drawScoreHero(doc, score, risk);

  doc.moveDown(0.8);
  sectionTitle(doc, 'Executive summary', 'A quick explanation for technical and non-technical readers.');
  infoBox(doc, 'What the score means', riskMeaning(risk), COLORS.soft, COLORS.text);

  doc.moveDown(0.35);
  sectionTitle(doc, 'At a glance', 'The most important results from this scan.');
  drawMetricGrid(doc, [
    ['Issues found', String(findings.length), 'Total findings detected'],
    ['Critical / High', String(counts.critical + counts.high), 'Needs prompt attention'],
    ['Checks completed', `${successfulEngines(scan)}/3`, 'Security engines finished'],
    ['Assessment', scan.assessmentStatus === 'complete' ? 'Complete' : 'Incomplete', 'Coverage status'],
  ]);

  doc.moveDown(0.25);
  const note = scan.assessmentStatus === 'complete'
    ? 'Start with Critical and High findings. Each issue explains what it means, why it matters, where it was found, and what to do next.'
    : 'This assessment is incomplete. The available findings are useful, but the score should not be treated as a complete assessment.';
  infoBox(doc, scan.assessmentStatus === 'complete' ? 'How to read this report' : 'Important notice', note,
    scan.assessmentStatus === 'complete' ? COLORS.blueLight : COLORS.amberLight,
    scan.assessmentStatus === 'complete' ? '#1d4ed8' : '#92400e');
}

function drawBrand(doc, y) {
  doc.roundedRect(PAGE.left, y, 38, 38, 9).fill(COLORS.accent);
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(21).text('✓', PAGE.left + 10, y + 7);
  doc.fillColor(COLORS.ink).font('Helvetica-Bold').fontSize(21).text('Secure', PAGE.left + 50, y + 3);
  doc.fillColor(COLORS.accentDark).text('Dev', PAGE.left + 113, y + 3);
  doc.font('Helvetica').fontSize(8.5).fillColor(COLORS.muted)
    .text('Application security made easier to understand', PAGE.left + 50, y + 27);
}

function drawPageHeader(doc, title, subtitle) {
  doc.y = PAGE.top;
  drawBrand(doc, doc.y);
  doc.y += 55;
  doc.font('Helvetica-Bold').fontSize(20).fillColor(COLORS.ink).text(title, PAGE.left, doc.y, { width: PAGE.width });
  doc.moveDown(0.25);
  doc.font('Helvetica').fontSize(9.5).fillColor(COLORS.muted)
    .text(subtitle, { width: PAGE.width, lineGap: 2 });
  doc.moveDown(0.75);
}

function drawScoreHero(doc, score, risk) {
  const y = doc.y;
  const h = 122;
  doc.roundedRect(PAGE.left, y, PAGE.width, h, 12).fill('#f1f5f9');
  doc.roundedRect(PAGE.left, y, 7, h, 3).fill(riskColor(risk));

  doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.muted)
    .text('OVERALL SECURITY SCORE', PAGE.left + 22, y + 18);
  doc.font('Helvetica-Bold').fontSize(40).fillColor(COLORS.ink)
    .text(score, PAGE.left + 22, y + 38, { width: 120 });
  doc.font('Helvetica').fontSize(11).fillColor(COLORS.muted)
    .text('/ 100', PAGE.left + 143, y + 60);

  doc.font('Helvetica-Bold').fontSize(18).fillColor(riskColor(risk))
    .text(risk, PAGE.left + 205, y + 25, { width: PAGE.width - 225 });
  doc.font('Helvetica-Bold').fontSize(9.5).fillColor(COLORS.text)
    .text('Risk level', PAGE.left + 205, y + 53);
  doc.font('Helvetica').fontSize(9).fillColor(COLORS.text)
    .text(riskMeaning(risk), PAGE.left + 205, y + 69, {
      width: PAGE.width - 225,
      lineGap: 2,
    });
  doc.y = y + h;
}

function drawMetricGrid(doc, metrics) {
  const gap = 9;
  const w = (PAGE.width - gap * 3) / 4;
  const y = doc.y;
  metrics.forEach((metric, index) => {
    const x = PAGE.left + index * (w + gap);
    doc.roundedRect(x, y, w, 64, 8).fill('#ffffff').stroke(COLORS.border);
    doc.font('Helvetica-Bold').fontSize(14).fillColor(COLORS.ink)
      .text(metric[1], x + 9, y + 10, { width: w - 18 });
    doc.font('Helvetica-Bold').fontSize(7.5).fillColor(COLORS.text)
      .text(metric[0], x + 9, y + 30, { width: w - 18 });
    doc.font('Helvetica').fontSize(6.8).fillColor(COLORS.muted)
      .text(metric[2], x + 9, y + 43, { width: w - 18, lineGap: 1 });
  });
  doc.y = y + 74;
}

function drawScoreBreakdown(doc, scan) {
  sectionTitle(doc, 'How the score is calculated', 'The final score is a weighted summary of five security areas. A lower sub-score means more issues were detected in that area.');
  const subScores = scan.subScores || {};

  Object.entries(SUBSCORE_INFO).forEach(([key, [label, explanation, weight]]) => {
    const score = Number.isFinite(Number(subScores[key])) ? Math.round(Number(subScores[key])) : null;
    const cardHeight = 62;
    ensureSpace(doc, cardHeight + 12);
    const y = doc.y;

    doc.roundedRect(PAGE.left, y, PAGE.width, cardHeight, 9).fill('#ffffff').stroke(COLORS.border);
    doc.font('Helvetica-Bold').fontSize(10.5).fillColor(COLORS.ink)
      .text(label, PAGE.left + 12, y + 10);
    doc.font('Helvetica').fontSize(8.1).fillColor(COLORS.muted)
      .text(`${weight}% weight — ${explanation}`, PAGE.left + 12, y + 27, { width: 360 });
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.text)
      .text(score === null ? 'N/A' : `${score}/100`, PAGE.left + 415, y + 11, { width: 70, align: 'right' });

    const barY = y + 45;
    doc.roundedRect(PAGE.left + 12, barY, PAGE.width - 92, 6, 3).fill('#e2e8f0');
    if (score !== null) {
      doc.roundedRect(PAGE.left + 12, barY, (PAGE.width - 92) * clamp(score, 0, 100) / 100, 6, 3).fill(scoreBarColor(score));
    }
    doc.y = y + cardHeight + 10;
  });

  infoBox(doc, 'How to interpret this section', 'The percentage beside each area is its contribution to the final score. For example, Dependency Security has a 30% weight, so dependency findings can have a substantial effect on the overall result.', COLORS.blueLight, '#1d4ed8');
}

function drawEngineCoverage(doc, scan) {
  sectionTitle(doc, 'Security checks performed', 'These checks work together to give you one report instead of separate scanner outputs.');
  const engines = [
    ['npm audit', scan.engineStatus?.npmAudit, 'Checks third-party packages for publicly known vulnerabilities.'],
    ['Secret scanner', scan.engineStatus?.secretScanner, 'Looks for credentials and other secret-like values in project files.'],
    ['Semgrep', scan.engineStatus?.semgrep, 'Checks source code for security-risk patterns.'],
  ];

  engines.forEach(([name, status, explanation]) => {
    ensureSpace(doc, 66);
    const y = doc.y;
    const color = status === 'success' ? '#15803d' : status === 'skipped' ? COLORS.muted : '#b91c1c';
    doc.roundedRect(PAGE.left, y, PAGE.width, 55, 8).fill('#ffffff').stroke(COLORS.border);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.ink).text(name, PAGE.left + 12, y + 10);
    doc.font('Helvetica').fontSize(8.3).fillColor(COLORS.muted)
      .text(explanation, PAGE.left + 12, y + 26, { width: 360 });
    doc.font('Helvetica-Bold').fontSize(8.5).fillColor(color)
      .text(status || 'unknown', PAGE.left + 410, y + 12, { width: 65, align: 'right' });
    doc.y = y + 66;
  });
}

function drawFindings(doc, scan) {
  const grouped = {};
  for (const finding of scan.findings || []) {
    if (!grouped[finding.category]) grouped[finding.category] = [];
    grouped[finding.category].push(finding);
  }

  Object.values(grouped).forEach((items) => items.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)));

  const categories = Object.entries(grouped);
  if (!categories.length) {
    ensureSpace(doc, 110);
    infoBox(doc, 'No issues detected', 'The completed security checks did not report any findings. This does not guarantee that the application is completely secure.', COLORS.greenLight, '#166534');
    return;
  }

  categories.forEach(([category, items]) => {
    ensureSpace(doc, 78);
    sectionTitle(doc, CATEGORY_LABELS[category] || category, CATEGORY_EXPLANATIONS[category] || 'Security findings reported for this category.');

    items.forEach((finding) => drawFindingCard(doc, finding, category));

    infoBox(doc, 'Recommended next step', CATEGORY_ACTIONS[category] || 'Review the reported code, apply the suggested remediation, and run the scan again.', COLORS.soft, COLORS.text);
  });
}

function drawFindingCard(doc, finding, category) {
  const severity = String(finding.severity || 'medium').toLowerCase();
  const title = finding.title || finding.ruleId || 'Security finding';
  const description = finding.description || 'The scanner reported a potential security issue.';
  const file = finding.file || finding.path || 'Location not provided';
  const line = finding.line ? `Line ${finding.line}` : '';
  const evidence = finding.evidence || finding.snippet || '';
  const impact = finding.impact || plainImpact(severity);
  const remediation = finding.remediation || finding.fix || 'Review the affected code and apply a secure implementation.';

  const titleHeight = doc.heightOfString(title, { width: PAGE.width - 155, font: 'Helvetica-Bold', size: 10.5, lineGap: 1 });
  const descHeight = doc.heightOfString(description, { width: PAGE.width - 32, font: 'Helvetica', size: 8.5, lineGap: 2 });
  const evidenceHeight = evidence ? doc.heightOfString(String(evidence), { width: PAGE.width - 44, font: 'Courier', size: 7.2, lineGap: 1 }) : 0;
  const impactHeight = doc.heightOfString(impact, { width: PAGE.width - 32, font: 'Helvetica', size: 8.2, lineGap: 2 });
  const remediationHeight = doc.heightOfString(remediation, { width: PAGE.width - 32, font: 'Helvetica', size: 8.2, lineGap: 2 });
  const cardHeight = Math.max(150, 48 + titleHeight + descHeight + impactHeight + remediationHeight + (evidence ? evidenceHeight + 38 : 0) + (file ? 28 : 0));

  ensureSpace(doc, cardHeight + 14);
  const y = doc.y;
  doc.roundedRect(PAGE.left, y, PAGE.width, cardHeight, 10).fill('#ffffff').stroke(COLORS.border);

  const badgeWidth = 62;
  doc.roundedRect(PAGE.left + 12, y + 12, badgeWidth, 19, 9).fill(SEVERITY_BG[severity] || SEVERITY_BG.medium);
  doc.font('Helvetica-Bold').fontSize(8).fillColor(SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium)
    .text(severity.toUpperCase(), PAGE.left + 12, y + 17, { width: badgeWidth, align: 'center' });

  doc.font('Helvetica-Bold').fontSize(10.5).fillColor(COLORS.ink)
    .text(title, PAGE.left + 86, y + 12, { width: PAGE.width - 100, lineGap: 1 });

  let cursor = y + 38 + titleHeight;
  doc.font('Helvetica').fontSize(8.5).fillColor(COLORS.text)
    .text(description, PAGE.left + 16, cursor, { width: PAGE.width - 32, lineGap: 2 });
  cursor += descHeight + 9;

  if (file) {
    doc.font('Helvetica-Bold').fontSize(7.8).fillColor(COLORS.muted).text('WHERE:', PAGE.left + 16, cursor);
    doc.font('Courier').fontSize(7.6).fillColor(COLORS.text).text(`${file}${line ? ` • ${line}` : ''}`, PAGE.left + 55, cursor, { width: PAGE.width - 71 });
    cursor += 22;
  }

  if (evidence) {
    doc.font('Helvetica-Bold').fontSize(7.8).fillColor(COLORS.muted).text('EVIDENCE:', PAGE.left + 16, cursor);
    cursor += 12;
    doc.roundedRect(PAGE.left + 16, cursor, PAGE.width - 32, evidenceHeight + 12, 6).fill(COLORS.soft);
    doc.font('Courier').fontSize(7.2).fillColor(COLORS.text)
      .text(String(evidence), PAGE.left + 22, cursor + 6, { width: PAGE.width - 44, lineGap: 1 });
    cursor += evidenceHeight + 20;
  }

  doc.font('Helvetica-Bold').fontSize(7.8).fillColor(COLORS.muted).text('WHY IT MATTERS:', PAGE.left + 16, cursor);
  cursor += 12;
  doc.font('Helvetica').fontSize(8.2).fillColor(COLORS.text)
    .text(impact, PAGE.left + 16, cursor, { width: PAGE.width - 32, lineGap: 2 });
  cursor += impactHeight + 9;

  doc.font('Helvetica-Bold').fontSize(7.8).fillColor(COLORS.muted).text('WHAT TO DO:', PAGE.left + 16, cursor);
  cursor += 12;
  doc.font('Helvetica').fontSize(8.2).fillColor(COLORS.text)
    .text(remediation, PAGE.left + 16, cursor, { width: PAGE.width - 32, lineGap: 2 });

  doc.y = y + cardHeight + 10;
}

function drawMethodology(doc, scan) {
  sectionTitle(doc, 'What SecureDev scanned', 'SecureDev combines several focused checks into one assessment.');
  const rows = [
    ['1. Dependencies', 'npm audit checks project packages against known vulnerability advisories.'],
    ['2. Secrets', 'The secret scanner searches project files for credential-like values that should not be committed.'],
    ['3. Source code', 'Semgrep applies security rules to source code to identify potentially unsafe patterns.'],
    ['4. Heuristics', 'Additional lightweight checks look for common application-security risks such as unsafe uploads, access-control gaps, and sensitive response fields.'],
    ['5. Normalization', 'Duplicate detections are combined so the same underlying issue is not counted repeatedly.'],
    ['6. Scoring', 'Five weighted security areas are combined into the final score.'],
  ];

  rows.forEach(([label, text]) => {
    ensureSpace(doc, 70);
    const y = doc.y;
    doc.roundedRect(PAGE.left, y, PAGE.width, 58, 8).fill('#ffffff').stroke(COLORS.border);
    doc.font('Helvetica-Bold').fontSize(9.5).fillColor(COLORS.ink).text(label, PAGE.left + 12, y + 11);
    doc.font('Helvetica').fontSize(8.2).fillColor(COLORS.text).text(text, PAGE.left + 12, y + 28, { width: PAGE.width - 24, lineGap: 2 });
    doc.y = y + 69;
  });

  sectionTitle(doc, 'Limitations', 'Security scanners provide signals, not a guarantee of complete security.');
  infoBox(doc, 'Important', 'A finding should be reviewed in the context of the application. Pattern-based checks can miss issues or report code that is safe in its actual context. Use this report to prioritize review and remediation, then scan again after fixes.', COLORS.amberLight, '#92400e');

  if (scan.assessmentStatus === 'incomplete') {
    infoBox(doc, 'Assessment was incomplete', scan.error || 'One or more core checks did not complete. The available findings remain useful, but the assessment should not be considered complete.', COLORS.redLight, '#991b1b');
  }
}

function sectionTitle(doc, title, subtitle) {
  ensureSpace(doc, 48);
  doc.font('Helvetica-Bold').fontSize(13).fillColor(COLORS.ink).text(title, PAGE.left, doc.y, { width: PAGE.width });
  doc.moveDown(0.18);
  doc.font('Helvetica').fontSize(8.8).fillColor(COLORS.muted).text(subtitle, { width: PAGE.width, lineGap: 2 });
  doc.moveDown(0.55);
}

function infoBox(doc, title, body, background, titleColor) {
  const height = Math.max(52, doc.heightOfString(body, { width: PAGE.width - 34, font: 'Helvetica', size: 8.2, lineGap: 2 }) + 32);
  ensureSpace(doc, height + 8);
  const y = doc.y;
  doc.roundedRect(PAGE.left, y, PAGE.width, height, 8).fill(background);
  doc.font('Helvetica-Bold').fontSize(8.8).fillColor(titleColor).text(title, PAGE.left + 14, y + 11);
  doc.font('Helvetica').fontSize(8.2).fillColor(COLORS.text)
    .text(body, PAGE.left + 14, y + 27, { width: PAGE.width - 28, lineGap: 2 });
  doc.y = y + height + 8;
}

function ensureSpace(doc, needed) {
  const maxY = doc.page.height - PAGE.bottom;
  if (doc.y + needed > maxY) {
    doc.addPage();
    drawPageHeader(doc, 'Security assessment report', 'Continued from the previous page.');
  }
}

function severityCounts(findings) {
  return findings.reduce((acc, finding) => {
    const severity = String(finding.severity || 'medium').toLowerCase();
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
}

function successfulEngines(scan) {
  return Object.values(scan.engineStatus || {}).filter((status) => status === 'success').length;
}

function riskMeaning(risk) {
  const value = String(risk || '').toLowerCase();
  if (value.includes('critical')) return 'The scan found serious security issues that should be addressed before relying on the application in production.';
  if (value.includes('high')) return 'The scan found important security issues that deserve prompt review and remediation.';
  if (value.includes('medium')) return 'The scan found security issues that should be reviewed and fixed as part of normal hardening work.';
  if (value.includes('low')) return 'The scan found a smaller number of lower-risk issues, but they should still be reviewed.';
  if (value.includes('good')) return 'The completed checks did not identify major issues, but no automated scan can guarantee complete security.';
  return 'This score summarizes the findings detected by the completed security checks.';
}

function riskColor(risk) {
  const value = String(risk || '').toLowerCase();
  if (value.includes('critical')) return SEVERITY_COLORS.critical;
  if (value.includes('high')) return SEVERITY_COLORS.high;
  if (value.includes('medium')) return SEVERITY_COLORS.medium;
  if (value.includes('low')) return SEVERITY_COLORS.low;
  return COLORS.accentDark;
}

function scoreBarColor(score) {
  if (score < 40) return SEVERITY_COLORS.high;
  if (score < 70) return SEVERITY_COLORS.medium;
  return COLORS.accent;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function plainImpact(severity) {
  if (severity === 'critical') return 'This issue may create a serious path for attackers to compromise data, accounts, or application behavior.';
  if (severity === 'high') return 'This issue can create a significant security risk if an attacker can reach the affected code or configuration.';
  if (severity === 'medium') return 'This issue can weaken the application and may become more serious when combined with other weaknesses.';
  return 'This issue is lower risk, but fixing it can improve the overall security posture.';
}

function formatDate(value) {
  if (!value) return 'Not available';
  try { return new Date(value).toLocaleString(); } catch { return String(value); }
}

function formatDuration(ms) {
  const seconds = Math.max(0, Math.round(Number(ms) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return `${minutes}m ${remainder}s`;
}

module.exports = { generateScanPdf };
