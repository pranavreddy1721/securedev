const PDFDocument = require('pdfkit');

const PAGE = {
  left: 48,
  right: 48,
  top: 50,
  bottom: 58,
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
  pages.addPage('Security overview', 'Score breakdown and security checks used for this assessment.');
  drawScoreBreakdown(pages, scan);
  drawEngineCoverage(pages, scan);
  pages.addPage('Findings and remediation', 'Plain-language explanations of detected issues and practical next steps.');
  drawFindings(pages, scan);
  pages.addPage('How SecureDev produced this report', 'A transparent summary of the scanning process, scoring model, and limitations.');
  drawMethodology(pages, scan);
  pages.finish();
  doc.end();

  return pdf;
}

function createPageManager(doc) {
  let pageNumber = 1;
  let y = PAGE.top;

  const maxY = () => doc.page.height - PAGE.bottom;

  function drawFooter() {
    const lineY = doc.page.height - 42;
    doc.save();
    doc.strokeColor(COLORS.border).lineWidth(0.6)
      .moveTo(PAGE.left, lineY)
      .lineTo(doc.page.width - PAGE.right, lineY)
      .stroke();
    doc.font('Helvetica').fontSize(7.5).fillColor('#94a3b8')
      .text(`SecureDev Security Report  |  Page ${pageNumber}`, PAGE.left, lineY + 8, {
        width: PAGE.width,
        align: 'center',
        lineBreak: false,
      });
    doc.restore();
  }

  function drawHeader(title, subtitle, continuation = false) {
    drawBrand(doc, PAGE.top);
    y = PAGE.top + 55;
    writeAt(doc, title, PAGE.left, y, PAGE.width, 'Helvetica-Bold', continuation ? 16 : 20, COLORS.ink, 0);
    y += continuation ? 22 : 27;
    y = writeAt(doc, subtitle, PAGE.left, y, PAGE.width, 'Helvetica', 9.5, COLORS.muted, 2) + 13;
  }

  function addPage(title, subtitle) {
    drawFooter();
    doc.addPage();
    pageNumber += 1;
    drawHeader(title, subtitle, false);
  }

  function continuationPage() {
    drawFooter();
    doc.addPage();
    pageNumber += 1;
    drawHeader('Security report continued', 'The report continues below; no finding has been split across pages.', true);
  }

  function ensure(height) {
    if (y + height <= maxY()) return;
    continuationPage();
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

function drawCover(p, scan, project) {
  const doc = p.doc;
  drawBrand(doc, PAGE.top);
  p.y = PAGE.top + 72;

  p.y = writeAt(doc, 'Security Assessment Report', PAGE.left, p.y, PAGE.width, 'Helvetica-Bold', 27, COLORS.ink, 0) + 12;
  p.y = writeAt(doc, `Project: ${project?.name || 'Unknown project'}`, PAGE.left, p.y, PAGE.width, 'Helvetica', 11, COLORS.muted, 0) + 3;
  p.y = writeAt(doc, `Scan completed: ${formatDate(scan.completedAt)}`, PAGE.left, p.y, PAGE.width, 'Helvetica', 10, COLORS.muted, 0) + 2;
  if (scan.durationMs) p.y = writeAt(doc, `Scan duration: ${formatDuration(scan.durationMs)}`, PAGE.left, p.y, PAGE.width, 'Helvetica', 10, COLORS.muted, 0) + 10;

  drawScoreHero(p, scan);
  p.y += 14;

  drawSectionHeading(p, 'Executive summary', 'A quick explanation for technical and non-technical readers.');
  drawInfoBox(p, 'What the score means', riskMeaning(scan.riskBand), COLORS.soft, COLORS.text);
  p.y += 8;

  drawSectionHeading(p, 'At a glance', 'The most important results from this scan.');
  const findings = scan.findings || [];
  const counts = severityCounts(findings);
  drawMetricGrid(p, [
    ['Issues found', String(findings.length), 'Total findings detected'],
    ['Critical / High', String(counts.critical + counts.high), 'Needs prompt attention'],
    ['Checks completed', `${successfulEngines(scan)}/3`, 'Security engines finished'],
    ['Assessment', scan.assessmentStatus === 'complete' ? 'Complete' : 'Incomplete', 'Coverage status'],
  ]);

  p.y += 2;
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
  doc.font('Helvetica').fontSize(8.5).fillColor(COLORS.muted).text('Application security made easier to understand', PAGE.left + 50, y + 27, { lineBreak: false });
}

function drawScoreHero(p, scan) {
  const doc = p.doc;
  const h = 116;
  p.ensure(h);
  const y = p.y;
  const score = Number.isFinite(Number(scan.finalScore)) ? Number(scan.finalScore).toFixed(1) : 'N/A';
  const risk = scan.riskBand || 'Risk level unavailable';
  const rightX = PAGE.left + 205;
  const rightW = PAGE.width - 225;

  doc.roundedRect(PAGE.left, y, PAGE.width, h, 12).fill('#f1f5f9');
  doc.roundedRect(PAGE.left, y, 7, h, 3).fill(riskColor(risk));
  doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.muted).text('OVERALL SECURITY SCORE', PAGE.left + 22, y + 17, { lineBreak: false });
  doc.font('Helvetica-Bold').fontSize(38).fillColor(COLORS.ink).text(score, PAGE.left + 22, y + 38, { width: 115, lineBreak: false });
  doc.font('Helvetica').fontSize(11).fillColor(COLORS.muted).text('/ 100', PAGE.left + 143, y + 57, { lineBreak: false });
  doc.font('Helvetica-Bold').fontSize(17).fillColor(riskColor(risk)).text(risk, rightX, y + 23, { width: rightW, lineBreak: false });
  doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.text).text('Risk level', rightX, y + 49, { lineBreak: false });
  doc.font('Helvetica').fontSize(8.7).fillColor(COLORS.text).text(riskMeaning(risk), rightX, y + 64, { width: rightW, lineGap: 2 });
  p.y = y + h;
}

function drawSectionHeading(p, title, subtitle) {
  const titleH = p.doc.heightOfString(title, { width: PAGE.width, font: 'Helvetica-Bold', size: 14 });
  const subH = p.doc.heightOfString(subtitle, { width: PAGE.width, font: 'Helvetica', size: 8.8, lineGap: 2 });
  p.ensure(titleH + subH + 18);
  p.y = writeAt(p.doc, title, PAGE.left, p.y, PAGE.width, 'Helvetica-Bold', 14, COLORS.ink, 0) + 3;
  p.y = writeAt(p.doc, subtitle, PAGE.left, p.y, PAGE.width, 'Helvetica', 8.8, COLORS.muted, 2) + 10;
}

function drawInfoBox(p, title, body, fill, titleColor) {
  const bodyH = p.doc.heightOfString(body, { width: PAGE.width - 28, font: 'Helvetica', size: 8.5, lineGap: 2 });
  const h = 28 + bodyH + 12;
  p.ensure(h);
  const y = p.y;
  p.doc.roundedRect(PAGE.left, y, PAGE.width, h, 9).fill(fill);
  writeAt(p.doc, title, PAGE.left + 14, y + 10, PAGE.width - 28, 'Helvetica-Bold', 8.3, titleColor, 0);
  writeAt(p.doc, body, PAGE.left + 14, y + 25, PAGE.width - 28, 'Helvetica', 8.5, COLORS.text, 2);
  p.y = y + h;
}

function drawMetricGrid(p, metrics) {
  const gap = 9;
  const w = (PAGE.width - gap * 3) / 4;
  const h = 66;
  p.ensure(h);
  const y = p.y;
  metrics.forEach((metric, index) => {
    const x = PAGE.left + index * (w + gap);
    p.doc.roundedRect(x, y, w, h, 8).fill('#ffffff').stroke(COLORS.border);
    writeAt(p.doc, metric[1], x + 9, y + 9, w - 18, 'Helvetica-Bold', 13, COLORS.ink, 0, true);
    writeAt(p.doc, metric[0], x + 9, y + 29, w - 18, 'Helvetica-Bold', 7.2, COLORS.text, 0, true);
    writeAt(p.doc, metric[2], x + 9, y + 42, w - 18, 'Helvetica', 6.5, COLORS.muted, 1);
  });
  p.y = y + h + 10;
}

function drawScoreBreakdown(p, scan) {
  drawSectionHeading(p, 'How the score is calculated', 'The final score is a weighted summary of five security areas. A lower sub-score means more issues were detected in that area.');
  const subScores = scan.subScores || {};
  for (const [key, [label, explanation, weight]] of Object.entries(SUBSCORE_INFO)) {
    const score = Number.isFinite(Number(subScores[key])) ? Math.round(Number(subScores[key])) : null;
    const h = 70;
    p.ensure(h);
    const y = p.y;
    const barW = PAGE.width - 100;
    p.doc.roundedRect(PAGE.left, y, PAGE.width, h, 9).fill('#ffffff').stroke(COLORS.border);
    writeAt(p.doc, label, PAGE.left + 12, y + 9, 330, 'Helvetica-Bold', 10.5, COLORS.ink, 0, true);
    writeAt(p.doc, `${weight}% weight`, PAGE.left + 392, y + 9, 90, 'Helvetica-Bold', 7.5, COLORS.muted, 0, true, 'right');
    writeAt(p.doc, explanation, PAGE.left + 12, y + 27, 350, 'Helvetica', 7.8, COLORS.muted, 1.5);
    writeAt(p.doc, score === null ? 'N/A' : `${score}/100`, PAGE.left + 420, y + 27, 60, 'Helvetica-Bold', 9.5, COLORS.text, 0, true, 'right');
    p.doc.roundedRect(PAGE.left + 12, y + 51, barW, 6, 3).fill('#e2e8f0');
    if (score !== null) p.doc.roundedRect(PAGE.left + 12, y + 51, barW * clamp(score, 0, 100) / 100, 6, 3).fill(scoreBarColor(score));
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
    const h = 61;
    p.ensure(h);
    const y = p.y;
    const success = status === 'success';
    const statusLabel = success ? 'Completed' : status === 'skipped' ? 'Skipped' : 'Failed';
    const statusColor = success ? COLORS.greenText : status === 'skipped' ? COLORS.muted : '#b91c1c';
    p.doc.roundedRect(PAGE.left, y, PAGE.width, h, 8).fill('#ffffff').stroke(COLORS.border);
    writeAt(p.doc, name, PAGE.left + 12, y + 10, 250, 'Helvetica-Bold', 10, COLORS.ink, 0, true);
    writeAt(p.doc, statusLabel, PAGE.left + 390, y + 10, 90, 'Helvetica-Bold', 8, statusColor, 0, true, 'right');
    writeAt(p.doc, explanation, PAGE.left + 12, y + 29, PAGE.width - 24, 'Helvetica', 7.8, COLORS.muted, 1.5);
    p.y = y + h + 8;
  }
}

function drawFindings(p, scan) {
  const findings = [...(scan.findings || [])].sort((a, b) => {
    const severity = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
    return severity || String(a.category || '').localeCompare(String(b.category || ''));
  });
  if (!findings.length) {
    drawInfoBox(p, 'No findings detected', 'The completed scanners did not report an issue. This does not guarantee that the application is completely secure.', COLORS.green, COLORS.greenText);
    return;
  }
  const grouped = {};
  findings.forEach((finding) => {
    const key = finding.category || 'other';
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(finding);
  });

  for (const [category, categoryFindings] of Object.entries(grouped)) {
    const label = CATEGORY_LABELS[category] || humanize(category);
    const explanation = CATEGORY_EXPLANATIONS[category] || 'A security-related issue was detected in this area.';
    const headingH = p.doc.heightOfString(explanation, { width: PAGE.width, font: 'Helvetica', size: 8.5, lineGap: 2 }) + 42;
    p.ensure(headingH + 4);
    p.y = writeAt(p.doc, label, PAGE.left, p.y, PAGE.width, 'Helvetica-Bold', 14, COLORS.ink, 0) + 3;
    p.y = writeAt(p.doc, explanation, PAGE.left, p.y, PAGE.width, 'Helvetica', 8.5, COLORS.muted, 2) + 9;
    for (const finding of categoryFindings) {
      drawFindingCard(p, finding, category);
      p.y += 9;
    }
  }
}

function drawFindingCard(p, finding, category) {
  const doc = p.doc;
  const severity = String(finding.severity || 'medium').toLowerCase();
  const sevColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium;
  const sevBg = SEVERITY_BG[severity] || SEVERITY_BG.medium;
  const title = finding.title || 'Security finding';
  const description = finding.description || 'No detailed description was provided by the scanner.';
  const file = finding.file ? `${finding.file}${finding.line ? ` • Line ${finding.line}` : ''}` : 'Location not provided';
  const why = whyItMatters(severity);
  const action = finding.remediation || CATEGORY_ACTIONS[category] || 'Review the affected code, apply the recommended security control, and run the scan again.';
  const contentW = PAGE.width - 28;
  const descH = doc.heightOfString(description, { width: contentW, font: 'Helvetica', size: 8.3, lineGap: 2 });
  const fileH = doc.heightOfString(file, { width: contentW, font: 'Helvetica', size: 7.6, lineGap: 1.5 });
  const whyH = doc.heightOfString(why, { width: contentW, font: 'Helvetica', size: 8.1, lineGap: 2 });
  const actionH = doc.heightOfString(action, { width: contentW, font: 'Helvetica', size: 8.1, lineGap: 2 });
  const h = 130 + descH + fileH + whyH + actionH;

  p.ensure(h);
  const y = p.y;
  doc.roundedRect(PAGE.left, y, PAGE.width, h, 10).fill('#ffffff').stroke(COLORS.border);
  doc.roundedRect(PAGE.left, y, 7, h, 3).fill(sevColor);
  doc.roundedRect(PAGE.left + 14, y + 12, 54, 18, 8).fill(sevBg);
  writeAt(doc, severity.toUpperCase(), PAGE.left + 14, y + 17, 54, 'Helvetica-Bold', 7, sevColor, 0, true, 'center');
  writeAt(doc, title, PAGE.left + 78, y + 14, PAGE.width - 92, 'Helvetica-Bold', 10.5, COLORS.ink, 1.5);

  let cy = y + 48;
  cy = fieldBlock(doc, 'WHAT WAS FOUND', description, cy, contentW, 8.3);
  cy = fieldBlock(doc, 'WHERE', file, cy + 8, contentW, 7.6);
  cy = fieldBlock(doc, 'WHY IT MATTERS', why, cy + 8, contentW, 8.1);
  fieldBlock(doc, 'WHAT TO DO', action, cy + 8, contentW, 8.1);
  p.y = y + h;
}

function fieldBlock(doc, label, body, y, width, size) {
  writeAt(doc, label, PAGE.left + 14, y, width, 'Helvetica-Bold', 7.1, COLORS.muted, 0, true);
  const bodyY = y + 12;
  const h = doc.heightOfString(body, { width, font: 'Helvetica', size, lineGap: 2 });
  writeAt(doc, body, PAGE.left + 14, bodyY, width, 'Helvetica', size, COLORS.text, 2);
  return bodyY + h;
}

function drawMethodology(p, scan) {
  drawSectionHeading(p, 'What SecureDev scanned', 'SecureDev combines several focused checks into one assessment.');
  const steps = [
    ['1. Dependencies', 'npm audit checks project packages against known vulnerability advisories.'],
    ['2. Secrets', 'The secret scanner searches project files for credential-like values that should not be committed.'],
    ['3. Source code', 'Semgrep applies security rules to source code to identify potentially unsafe patterns.'],
    ['4. Heuristics', 'Additional lightweight checks look for common application-security risks such as unsafe uploads, access-control gaps, and sensitive response fields.'],
    ['5. Normalization', 'Duplicate detections are combined so the same underlying issue is not counted repeatedly.'],
    ['6. Scoring', 'Five weighted security areas are combined into the final score.'],
  ];
  for (const [title, body] of steps) {
    const bodyH = p.doc.heightOfString(body, { width: PAGE.width - 30, font: 'Helvetica', size: 8.5, lineGap: 2 });
    const h = 25 + bodyH;
    p.ensure(h);
    const y = p.y;
    p.doc.roundedRect(PAGE.left, y, PAGE.width, h, 8).fill('#ffffff').stroke(COLORS.border);
    writeAt(p.doc, title, PAGE.left + 14, y + 9, PAGE.width - 28, 'Helvetica-Bold', 9.5, COLORS.ink, 0);
    writeAt(p.doc, body, PAGE.left + 14, y + 25, PAGE.width - 28, 'Helvetica', 8.5, COLORS.text, 2);
    p.y = y + h + 8;
  }
  drawSectionHeading(p, 'Assessment limitations', 'What this report can and cannot tell you.');
  drawInfoBox(p, 'Important', scan.assessmentStatus === 'complete'
    ? 'A completed scan means the configured checks finished successfully. It does not prove that the application is free of vulnerabilities. Pattern-based and dependency checks can miss issues that require business context or manual review.'
    : 'This assessment is incomplete. Findings can still be useful, but the overall score should not be treated as a complete representation of the application security posture.', COLORS.amber, COLORS.amberText);
}

function writeAt(doc, value, x, y, width, font, size, color, lineGap = 0, noWrap = false, align = 'left') {
  const text = String(value ?? '');
  doc.font(font).fontSize(size).fillColor(color);
  if (noWrap) {
    doc.text(text, x, y, { width, align, lineBreak: false });
    return y + size;
  }
  const h = doc.heightOfString(text, { width, font, size, lineGap });
  doc.text(text, x, y, { width, lineGap, align });
  return y + h;
}

function severityCounts(findings) {
  return findings.reduce((acc, finding) => {
    const severity = String(finding.severity || 'low').toLowerCase();
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
}

function successfulEngines(scan) {
  return Object.values(scan.engineStatus || {}).filter((status) => status === 'success').length;
}

function riskMeaning(risk) {
  const text = String(risk || '').toLowerCase();
  if (text.includes('low')) return 'Few security concerns were detected by the completed checks. Continue reviewing findings and keep dependencies and security controls up to date.';
  if (text.includes('medium')) return 'The scan found security concerns that should be reviewed and addressed. The score is a summary of the checks that completed.';
  if (text.includes('high')) return 'The scan found important security concerns that should be addressed promptly, especially issues rated Critical or High.';
  if (text.includes('critical')) return 'The scan found serious security concerns that require prompt attention before relying on the affected functionality.';
  return 'Review the findings and scanner coverage before treating this assessment as a complete security picture.';
}

function whyItMatters(severity) {
  if (severity === 'critical') return 'This finding represents a critical security concern and should be addressed before release when the affected code is reachable.';
  if (severity === 'high') return 'This finding represents a significant security concern and should normally be addressed before release when the affected code is reachable.';
  if (severity === 'medium') return 'This finding represents a moderate security concern. It should be reviewed and fixed as part of normal security maintenance.';
  return 'This finding is a lower-severity signal. Review it in the context of the affected feature and address it when practical.';
}

function humanize(value) {
  return String(value || 'Other').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, (c) => c.toUpperCase());
}

function riskColor(risk) {
  const text = String(risk || '').toLowerCase();
  if (text.includes('critical')) return '#dc2626';
  if (text.includes('high')) return '#ea580c';
  if (text.includes('medium')) return '#d97706';
  return '#16a34a';
}

function scoreBarColor(score) {
  if (score >= 80) return '#16a34a';
  if (score >= 60) return '#d97706';
  if (score >= 40) return '#ea580c';
  return '#dc2626';
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function formatDuration(ms) {
  const seconds = Math.max(0, Math.round(Number(ms) / 1000));
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function formatDate(value) {
  if (!value) return 'Unavailable';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Unavailable';
  return date.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
}

module.exports = { generateScanPdf };
