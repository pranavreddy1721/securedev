const PDFDocument = require('pdfkit');

const PAGE = {
  left: 48,
  right: 48,
  top: 48,
  bottom: 62,
  width: 499,
};

const COLORS = {
  ink: '#0f172a',
  text: '#334155',
  muted: '#64748b',
  border: '#dbe3ec',
  accent: '#10b981',
  accentDark: '#047857',
  soft: '#f8fafc',
  blue: '#eff6ff',
  blueText: '#1d4ed8',
  green: '#ecfdf5',
  greenText: '#166534',
  amber: '#fffbeb',
  amberText: '#92400e',
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
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

async function generateScanPdf(scan, project) {
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

  const chunks = [];
  const pdf = new Promise((resolve, reject) => {
    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });

  const pages = createPageManager(doc);
  drawCover(pages, scan, project);
  newPage(pages, 'Security overview', 'Score breakdown and security checks used for this assessment.');
  drawScoreBreakdown(pages, scan);
  drawEngineCoverage(pages, scan);
  newPage(pages, 'Findings and remediation', 'Plain-language explanations of detected issues and practical next steps.');
  drawFindings(pages, scan);
  newPage(pages, 'How SecureDev produced this report', 'A transparent summary of the scanning process, scoring model, and limitations.');
  drawMethodology(pages, scan);
  pages.finish();
  doc.end();

  return pdf;
}

function createPageManager(doc) {
  let pageNumber = 1;
  let y = PAGE.top;

  function drawFooter() {
    const footerY = doc.page.height - 38;
    doc.save();
    doc.strokeColor(COLORS.border).lineWidth(0.6)
      .moveTo(PAGE.left, footerY - 8)
      .lineTo(doc.page.width - PAGE.right, footerY - 8)
      .stroke();
    doc.font('Helvetica').fontSize(7.5).fillColor('#94a3b8')
      .text(`SecureDev Security Report  |  Page ${pageNumber}`, PAGE.left, footerY, {
        width: PAGE.width,
        align: 'center',
        lineBreak: false,
      });
    doc.restore();
  }

  function addPage(title, subtitle) {
    drawFooter();
    doc.addPage();
    pageNumber += 1;
    y = PAGE.top;
    drawBrand(doc, y);
    y += 56;
    text(doc, title, PAGE.left, y, PAGE.width, 'Helvetica-Bold', 20, COLORS.ink, 0);
    y += 27;
    y = text(doc, subtitle, PAGE.left, y, PAGE.width, 'Helvetica', 9.5, COLORS.muted, 2);
    y += 15;
  }

  function ensure(height) {
    const bottom = doc.page.height - PAGE.bottom - 8;
    if (y + height <= bottom) return;
    drawFooter();
    doc.addPage();
    pageNumber += 1;
    y = PAGE.top;
    drawBrand(doc, y);
    y += 56;
    text(doc, 'Security report continued', PAGE.left, y, PAGE.width, 'Helvetica-Bold', 16, COLORS.ink, 0);
    y += 26;
  }

  function finish() {
    drawFooter();
  }

  return {
    doc,
    get y() { return y; },
    set y(value) { y = value; },
    ensure,
    addPage,
    finish,
  };
}

function newPage(pages, title, subtitle) {
  pages.addPage(title, subtitle);
}

function drawCover(p, scan, project) {
  const doc = p.doc;
  drawBrand(doc, PAGE.top);
  p.y = 116;

  p.y = text(doc, 'Security Assessment Report', PAGE.left, p.y, PAGE.width, 'Helvetica-Bold', 27, COLORS.ink, 0) + 8;
  p.y = text(doc, `Project: ${project?.name || 'Unknown project'}`, PAGE.left, p.y, PAGE.width, 'Helvetica', 11, COLORS.muted, 1) + 2;
  p.y = text(doc, `Scan completed: ${formatDate(scan.completedAt)}`, PAGE.left, p.y, PAGE.width, 'Helvetica', 10, COLORS.muted, 1) + 2;
  if (scan.durationMs) p.y = text(doc, `Scan duration: ${formatDuration(scan.durationMs)}`, PAGE.left, p.y, PAGE.width, 'Helvetica', 10, COLORS.muted, 1) + 4;

  p.y += 18;
  drawScoreHero(p, scan);
  p.y += 18;

  drawSectionHeading(p, 'Executive summary', 'A quick explanation for technical and non-technical readers.');
  drawInfoBox(p, 'What the score means', riskMeaning(scan.riskBand), COLORS.soft, COLORS.text);
  p.y += 10;

  drawSectionHeading(p, 'At a glance', 'The most important results from this scan.');
  const findings = scan.findings || [];
  const counts = severityCounts(findings);
  drawMetricGrid(p, [
    ['Issues found', String(findings.length), 'Total findings detected'],
    ['Critical / High', String(counts.critical + counts.high), 'Needs prompt attention'],
    ['Checks completed', `${successfulEngines(scan)}/3`, 'Security engines finished'],
    ['Assessment', scan.assessmentStatus === 'complete' ? 'Complete' : 'Incomplete', 'Coverage status'],
  ]);

  p.y += 5;
  drawInfoBox(
    p,
    scan.assessmentStatus === 'complete' ? 'How to read this report' : 'Important notice',
    scan.assessmentStatus === 'complete'
      ? 'Start with Critical and High findings. Each issue explains what it means, why it matters, where it was found, and what to do next.'
      : 'This assessment is incomplete. The available findings are useful, but the score should not be treated as a complete assessment.',
    scan.assessmentStatus === 'complete' ? COLORS.blue : COLORS.amber,
    scan.assessmentStatus === 'complete' ? COLORS.blueText : COLORS.amberText,
  );
}

function drawBrand(doc, y) {
  doc.roundedRect(PAGE.left, y, 38, 38, 9).fill(COLORS.accent);
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(21).text('✓', PAGE.left + 10, y + 7, { lineBreak: false });
  doc.fillColor(COLORS.ink).font('Helvetica-Bold').fontSize(21).text('Secure', PAGE.left + 50, y + 3, { lineBreak: false });
  doc.fillColor(COLORS.accentDark).text('Dev', PAGE.left + 113, y + 3, { lineBreak: false });
  doc.font('Helvetica').fontSize(8.5).fillColor(COLORS.muted)
    .text('Application security made easier to understand', PAGE.left + 50, y + 27, { lineBreak: false });
}

function drawScoreHero(p, scan) {
  const doc = p.doc;
  const y = p.y;
  const h = 116;
  p.ensure(h + 2);
  const score = Number.isFinite(Number(scan.finalScore)) ? Number(scan.finalScore).toFixed(1) : 'N/A';
  const risk = scan.riskBand || 'Risk level unavailable';

  doc.roundedRect(PAGE.left, y, PAGE.width, h, 12).fill('#f1f5f9');
  doc.roundedRect(PAGE.left, y, 7, h, 3).fill(riskColor(risk));
  doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.muted)
    .text('OVERALL SECURITY SCORE', PAGE.left + 22, y + 17, { lineBreak: false });
  doc.font('Helvetica-Bold').fontSize(38).fillColor(COLORS.ink)
    .text(score, PAGE.left + 22, y + 37, { width: 125, lineBreak: false });
  doc.font('Helvetica').fontSize(11).fillColor(COLORS.muted)
    .text('/ 100', PAGE.left + 143, y + 57, { lineBreak: false });

  doc.font('Helvetica-Bold').fontSize(17).fillColor(riskColor(risk))
    .text(risk, PAGE.left + 205, y + 23, { width: PAGE.width - 225, lineBreak: false });
  doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.text)
    .text('Risk level', PAGE.left + 205, y + 48, { lineBreak: false });
  const meaning = riskMeaning(risk);
  const meaningHeight = doc.heightOfString(meaning, { width: PAGE.width - 225, font: 'Helvetica', size: 8.7, lineGap: 2 });
  doc.font('Helvetica').fontSize(8.7).fillColor(COLORS.text)
    .text(meaning, PAGE.left + 205, y + 64, { width: PAGE.width - 225, lineGap: 2, height: meaningHeight });
  p.y = y + h;
}

function drawMetricGrid(p, metrics) {
  const gap = 9;
  const w = (PAGE.width - gap * 3) / 4;
  const h = 64;
  p.ensure(h);
  const y = p.y;
  metrics.forEach((metric, index) => {
    const x = PAGE.left + index * (w + gap);
    p.doc.roundedRect(x, y, w, h, 8).fill('#ffffff').stroke(COLORS.border);
    p.doc.font('Helvetica-Bold').fontSize(13).fillColor(COLORS.ink)
      .text(metric[1], x + 9, y + 9, { width: w - 18, lineBreak: false });
    p.doc.font('Helvetica-Bold').fontSize(7.3).fillColor(COLORS.text)
      .text(metric[0], x + 9, y + 29, { width: w - 18, lineBreak: false });
    p.doc.font('Helvetica').fontSize(6.6).fillColor(COLORS.muted)
      .text(metric[2], x + 9, y + 42, { width: w - 18, lineGap: 1 });
  });
  p.y = y + h + 10;
}

function drawScoreBreakdown(p, scan) {
  drawSectionHeading(p, 'How the score is calculated', 'The final score is a weighted summary of five security areas. A lower sub-score means more issues were detected in that area.');
  const subScores = scan.subScores || {};
  for (const [key, [label, explanation, weight]] of Object.entries(SUBSCORE_INFO)) {
    const score = Number.isFinite(Number(subScores[key])) ? Math.round(Number(subScores[key])) : null;
    const h = 67;
    p.ensure(h);
    const y = p.y;
    p.doc.roundedRect(PAGE.left, y, PAGE.width, h, 9).fill('#ffffff').stroke(COLORS.border);
    p.doc.font('Helvetica-Bold').fontSize(10.5).fillColor(COLORS.ink)
      .text(label, PAGE.left + 12, y + 10, { lineBreak: false });
    p.doc.font('Helvetica').fontSize(8).fillColor(COLORS.muted)
      .text(`${weight}% weight — ${explanation}`, PAGE.left + 12, y + 27, { width: 350, lineGap: 1.5 });
    p.doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.text)
      .text(score === null ? 'N/A' : `${score}/100`, PAGE.left + 415, y + 11, { width: 70, align: 'right', lineBreak: false });
    p.doc.roundedRect(PAGE.left + 12, y + 49, PAGE.width - 92, 6, 3).fill('#e2e8f0');
    if (score !== null) {
      p.doc.roundedRect(PAGE.left + 12, y + 49, (PAGE.width - 92) * clamp(score, 0, 100) / 100, 6, 3).fill(scoreBarColor(score));
    }
    p.y = y + h + 9;
  }
  drawInfoBox(p, 'How to interpret this section', 'The percentage beside each area is its contribution to the final score. Dependency Security has a 30% weight, so dependency findings can have a substantial effect on the overall result.', COLORS.blue, COLORS.blueText);
}

function drawEngineCoverage(p, scan) {
  drawSectionHeading(p, 'Security checks performed', 'These checks work together to give you one report instead of separate scanner outputs.');
  const engines = [
    ['npm audit', scan.engineStatus?.npmAudit, 'Checks third-party packages for publicly known vulnerabilities.'],
    ['Secret scanner', scan.engineStatus?.secretScanner, 'Looks for credentials and other secret-like values in project files.'],
    ['Semgrep', scan.engineStatus?.semgrep, 'Checks source code for security-risk patterns.'],
  ];
  for (const [name, status, explanation] of engines) {
    const h = 59;
    p.ensure(h);
    const y = p.y;
    const color = status === 'success' ? '#15803d' : status === 'skipped' ? COLORS.muted : '#b91c1c';
    p.doc.roundedRect(PAGE.left, y, PAGE.width, h, 8).fill('#ffffff').stroke(COLORS.border);
    p.doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.ink).text(name, PAGE.left + 12, y + 10, { lineBreak: false });
    p.doc.font('Helvetica').fontSize(8.1).fillColor(COLORS.muted).text(explanation, PAGE.left + 12, y + 27, { width: 355, lineGap: 1.5 });
    p.doc.font('Helvetica-Bold').fontSize(8.5).fillColor(color).text(humanStatus(status), PAGE.left + 410, y + 12, { width: 65, align: 'right', lineBreak: false });
    p.y = y + h + 8;
  }
}

function drawFindings(p, scan) {
  const grouped = {};
  for (const finding of scan.findings || []) {
    if (!grouped[finding.category]) grouped[finding.category] = [];
    grouped[finding.category].push(finding);
  }
  Object.values(grouped).forEach((items) => items.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)));
  const categories = Object.entries(grouped);

  if (!categories.length) {
    drawInfoBox(p, 'No issues detected', 'The completed security checks did not report any findings. This does not guarantee that the application is completely secure.', COLORS.green, COLORS.greenText);
    return;
  }

  for (const [category, items] of categories) {
    drawSectionHeading(p, CATEGORY_LABELS[category] || category, CATEGORY_EXPLANATIONS[category] || 'Security findings reported for this category.');
    for (const finding of items) drawFindingCard(p, finding, category);
    drawInfoBox(p, 'Recommended next step', CATEGORY_ACTIONS[category] || 'Review the reported code, apply the suggested remediation, and run the scan again.', COLORS.soft, COLORS.text);
    p.y += 8;
  }
}

function drawFindingCard(p, finding, category) {
  const severity = String(finding.severity || 'medium').toLowerCase();
  const title = finding.title || finding.ruleId || 'Security finding';
  const description = finding.description || 'The scanner reported a potential security issue.';
  const file = finding.file || finding.path || '';
  const line = finding.line ? `Line ${finding.line}` : '';
  const technical = description;
  const impact = severityImpact(severity);
  const remediation = CATEGORY_ACTIONS[category] || 'Review the affected code, apply a secure implementation, and run the scan again.';

  const titleWidth = PAGE.width - 112;
  const titleH = measure(p.doc, title, titleWidth, 'Helvetica-Bold', 10.5, 1);
  const descH = measure(p.doc, description, PAGE.width - 32, 'Helvetica', 8.5, 2);
  const locationH = file ? measure(p.doc, softWrap(file) + (line ? ` • ${line}` : ''), PAGE.width - 88, 'Courier', 7.4, 1) : 0;
  const technicalH = measure(p.doc, technical, PAGE.width - 32, 'Helvetica', 8.2, 2);
  const impactH = measure(p.doc, impact, PAGE.width - 32, 'Helvetica', 8.2, 2);
  const remediationH = measure(p.doc, remediation, PAGE.width - 32, 'Helvetica', 8.2, 2);

  const cardHeight = 48 + titleH + descH + (file ? locationH + 25 : 0) + technicalH + impactH + remediationH + 72;
  p.ensure(cardHeight + 10);
  const y = p.y;
  p.doc.roundedRect(PAGE.left, y, PAGE.width, cardHeight, 10).fill('#ffffff').stroke(COLORS.border);

  const badgeWidth = 62;
  p.doc.roundedRect(PAGE.left + 12, y + 12, badgeWidth, 19, 9).fill(SEVERITY_BG[severity] || SEVERITY_BG.medium);
  p.doc.font('Helvetica-Bold').fontSize(8).fillColor(SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium)
    .text(severity.toUpperCase(), PAGE.left + 12, y + 17, { width: badgeWidth, align: 'center', lineBreak: false });
  p.y = y + 12;
  text(p.doc, title, PAGE.left + 86, p.y, titleWidth, 'Helvetica-Bold', 10.5, COLORS.ink, 1);

  let cursor = y + 40 + titleH;
  cursor = drawLabeledText(p.doc, 'WHAT WAS FOUND', description, cursor, PAGE.left + 16, PAGE.width - 32);
  if (file) cursor = drawLabeledText(p.doc, 'WHERE', softWrap(file) + (line ? ` • ${line}` : ''), cursor, PAGE.left + 16, PAGE.width - 32, 'Courier', 7.4);
  cursor = drawLabeledText(p.doc, 'WHY IT MATTERS', impact, cursor, PAGE.left + 16, PAGE.width - 32);
  cursor = drawLabeledText(p.doc, 'WHAT TO DO', remediation, cursor, PAGE.left + 16, PAGE.width - 32);

  p.y = y + cardHeight + 10;
}

function drawLabeledText(doc, label, value, y, x, width, fontName = 'Helvetica', fontSize = 8.2) {
  doc.font('Helvetica-Bold').fontSize(7.5).fillColor(COLORS.muted).text(label, x, y, { width, lineBreak: false });
  y += 12;
  const h = measure(doc, value, width, fontName, fontSize, 2);
  doc.font(fontName).fontSize(fontSize).fillColor(COLORS.text).text(value, x, y, { width, lineGap: 2, height: h });
  return y + h + 9;
}

function drawMethodology(p, scan) {
  drawSectionHeading(p, 'What SecureDev scanned', 'SecureDev combines several focused checks into one assessment.');
  const rows = [
    ['1. Dependencies', 'npm audit checks project packages against known vulnerability advisories.'],
    ['2. Secrets', 'The secret scanner searches project files for credential-like values that should not be committed.'],
    ['3. Source code', 'Semgrep applies security rules to source code to identify potentially unsafe patterns.'],
    ['4. Heuristics', 'Additional lightweight checks look for common application-security risks such as unsafe uploads, access-control gaps, and sensitive response fields.'],
    ['5. Normalization', 'Duplicate detections are combined so the same underlying issue is not counted repeatedly.'],
    ['6. Scoring', 'Five weighted security areas are combined into the final score.'],
  ];
  for (const [title, body] of rows) {
    const bodyH = measure(p.doc, body, PAGE.width - 28, 'Helvetica', 8.6, 2);
    p.ensure(bodyH + 42);
    const y = p.y;
    p.doc.roundedRect(PAGE.left, y, PAGE.width, bodyH + 34, 8).fill('#ffffff').stroke(COLORS.border);
    p.doc.font('Helvetica-Bold').fontSize(9.5).fillColor(COLORS.ink).text(title, PAGE.left + 12, y + 9, { lineBreak: false });
    p.doc.font('Helvetica').fontSize(8.6).fillColor(COLORS.text).text(body, PAGE.left + 12, y + 25, { width: PAGE.width - 24, lineGap: 2, height: bodyH });
    p.y = y + bodyH + 43;
  }

  drawSectionHeading(p, 'Assessment limitations', 'What this report can and cannot tell you.');
  drawInfoBox(p, 'Important', 'A completed scan means the configured checks finished successfully. It does not prove that the application is free of vulnerabilities. Pattern-based and dependency checks can miss issues that require business context or manual review.', COLORS.amber, COLORS.amberText);
  if (scan.assessmentStatus !== 'complete') {
    drawInfoBox(p, 'Coverage warning', 'This scan is marked incomplete. Review the failed or skipped security engine before relying on the score as a complete assessment.', COLORS.amber, COLORS.amberText);
  }
}

function drawSectionHeading(p, title, subtitle) {
  const titleH = measure(p.doc, title, PAGE.width, 'Helvetica-Bold', 14.5, 1);
  const subH = measure(p.doc, subtitle, PAGE.width, 'Helvetica', 8.8, 2);
  p.ensure(titleH + subH + 25);
  p.y = text(p.doc, title, PAGE.left, p.y, PAGE.width, 'Helvetica-Bold', 14.5, COLORS.ink, 1) + 3;
  p.y = text(p.doc, subtitle, PAGE.left, p.y, PAGE.width, 'Helvetica', 8.8, COLORS.muted, 2) + 12;
}

function drawInfoBox(p, title, body, background, titleColor) {
  const bodyH = measure(p.doc, body, PAGE.width - 28, 'Helvetica', 8.5, 2);
  const h = bodyH + 39;
  p.ensure(h);
  const y = p.y;
  p.doc.roundedRect(PAGE.left, y, PAGE.width, h, 9).fill(background).stroke(COLORS.border);
  p.doc.font('Helvetica-Bold').fontSize(8.5).fillColor(titleColor).text(title, PAGE.left + 14, y + 10, { width: PAGE.width - 28 });
  p.doc.font('Helvetica').fontSize(8.5).fillColor(COLORS.text).text(body, PAGE.left + 14, y + 25, { width: PAGE.width - 28, lineGap: 2, height: bodyH });
  p.y = y + h + 10;
}

function text(doc, value, x, y, width, fontName, fontSize, color, lineGap) {
  const str = String(value ?? '');
  const h = measure(doc, str, width, fontName, fontSize, lineGap);
  doc.font(fontName).fontSize(fontSize).fillColor(color).text(str, x, y, { width, lineGap, height: h });
  return y + h;
}

function measure(doc, value, width, fontName, fontSize, lineGap = 0) {
  return Math.max(1, doc.heightOfString(String(value ?? ''), { width, font: fontName, size: fontSize, lineGap }));
}

function softWrap(value) {
  return String(value || '').replace(/([\\/._:-])/g, '$1\u200b');
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

function humanStatus(status) {
  if (status === 'success') return 'Completed';
  if (status === 'skipped') return 'Skipped';
  if (status === 'failed') return 'Failed';
  if (status === 'pending') return 'Pending';
  return 'Unknown';
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

function riskColor(risk) {
  if (risk === 'Critical Risk') return '#b91c1c';
  if (risk === 'High Risk') return '#ea580c';
  if (risk === 'Medium Risk') return '#d97706';
  return '#15803d';
}

function scoreBarColor(score) {
  if (score < 40) return '#dc2626';
  if (score < 70) return '#d97706';
  return '#10b981';
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, Number(value) || 0));
}

function formatDuration(ms) {
  const seconds = Math.max(0, Math.round(Number(ms || 0) / 1000));
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function formatDate(value) {
  if (!value) return 'Not available';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Not available';
  return date.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
}

module.exports = { generateScanPdf };
