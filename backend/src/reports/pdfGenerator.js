const PDFDocument = require('pdfkit');

const PAGE = {
  left: 42,
  right: 42,
  top: 42,
  bottom: 48,
  headerBottom: 84,
  footerY: 790,
  width: 511,
  contentTop: 105,
  contentBottom: 775,
};

const C = {
  ink: '#0b1b3a', text: '#334155', muted: '#64748b', lightMuted: '#94a3b8',
  border: '#d8e2ec', white: '#ffffff', header: '#f3fbf8', accent: '#10b981', accentDark: '#047857',
  tealSoft: '#e8f8f2', blue: '#eff6ff', blueText: '#1d4ed8', green: '#ecfdf5', greenText: '#166534',
  amber: '#fff7e6', amberText: '#b45309', red: '#fef2f2', redText: '#b91c1c',
  orange: '#fff7ed', orangeText: '#c2410c', slate: '#f8fafc', slate2: '#eef3f7',
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV = {
  critical: ['#dc2626', '#fee2e2'], high: ['#dc2626', '#fee2e2'],
  medium: ['#ea580c', '#ffedd5'], low: ['#2563eb', '#dbeafe'],
};

const CATEGORY_LABELS = {
  vulnerableDependencies: 'Vulnerable Dependencies', hardcodedSecrets: 'Hardcoded Secrets',
  injectionFlaws: 'Injection Flaws', xss: 'Cross-Site Scripting (XSS)',
  brokenAuthentication: 'Broken Authentication', securityMisconfiguration: 'Security Misconfiguration',
  insecureFileUploads: 'Insecure File Uploads', brokenAccessControl: 'Broken Access Control',
  sensitiveDataExposure: 'Sensitive Data Exposure',
};

const CATEGORY_EXPLANATIONS = {
  vulnerableDependencies: 'Third-party packages and known vulnerabilities.',
  hardcodedSecrets: 'Credentials or secret-like values in source code.',
  injectionFlaws: 'Common injection and unsafe-input patterns in application code.',
  xss: 'Untrusted content that may be rendered unsafely in a browser.',
  brokenAuthentication: 'Protection around user identity, sessions and access.',
  securityMisconfiguration: 'Security-sensitive application configuration.',
  insecureFileUploads: 'Uploaded content that may not be validated or stored safely.',
  brokenAccessControl: 'Checks that control who can access actions or resources.',
  sensitiveDataExposure: 'Sensitive fields that may be exposed through application responses.',
};

const CATEGORY_ACTIONS = {
  vulnerableDependencies: 'Update the affected package to a patched version and run the scan again.',
  hardcodedSecrets: 'Remove the secret, rotate the credential, and store future secrets in environment variables or a secret manager.',
  injectionFlaws: 'Use safe APIs, validate input, constrain accepted values, and add a regression test.',
  xss: 'Encode untrusted output, avoid unsafe HTML insertion, and validate input where appropriate.',
  brokenAuthentication: 'Review authentication and session checks and add tests for unauthorized access.',
  securityMisconfiguration: 'Apply a secure configuration and verify the behavior in a production-like environment.',
  insecureFileUploads: 'Restrict file types and sizes, validate content, store uploads safely, and prevent execution.',
  brokenAccessControl: 'Add an explicit authorization check before the sensitive operation and test denied access.',
  sensitiveDataExposure: 'Return only required fields and remove secrets, tokens, password hashes and other private values.',
};

const SUBSCORES = [
  ['dependency', 'Dependency Security', 'Third-party packages and known vulnerabilities.', 30],
  ['authentication', 'Authentication', 'Protection around user identity and access.', 20],
  ['secrets', 'Secrets Detection', 'Credentials or secret-like values in source code.', 20],
  ['owaspCompliance', 'Application Security', 'Common application security risks found in code.', 20],
  ['configuration', 'Configuration', 'Security-sensitive application configuration.', 10],
];

async function generateScanPdf(scan, project) {
  const doc = new PDFDocument({
    size: 'A4', margins: { top: 0, bottom: 0, left: 0, right: 0 },
    info: {
      Title: `SecureDev Security Assessment Report - ${project?.name || 'Project'}`,
      Author: 'SecureDev', Subject: 'Application security assessment',
    },
    autoFirstPage: false,
  });

  const chunks = [];
  const pdf = new Promise((resolve, reject) => {
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });

  const pages = createPages(doc);
  drawPage1(pages, scan, project);
  drawPage2(pages, scan);
  drawPage3(pages, scan);
  drawPage4(pages, scan);
  drawPage5(pages, scan);
  drawPage6(pages, scan);

  doc.end();
  return pdf;
}

function createPages(doc) {
  let pageNo = 0;
  function startPage(title, subtitle, options = {}) {
    doc.addPage();
    pageNo += 1;
    drawHeader(doc, pageNo, title, subtitle, options);
    drawFooter(doc, pageNo);
    return { doc, x: PAGE.left, y: options.contentY || PAGE.contentTop, width: PAGE.width, pageNo };
  }
  return { startPage, doc, get pageNo() { return pageNo; } };
}

function drawHeader(d, pageNo, title, subtitle, options = {}) {
  d.save();
  d.rect(0, 0, d.page.width, 86).fill(C.white);
  d.rect(0, 0, d.page.width, 86).fill(C.header);
  d.rect(0, 85, d.page.width, 1).fill(C.border);
  drawLogo(d, 28, 18);
  d.font('Helvetica-Bold').fontSize(8).fillColor(C.ink)
    .text('SECURITY ASSESSMENT REPORT', 365, 20, { width: 185, align: 'right', lineBreak: false });
  d.font('Helvetica').fontSize(7).fillColor(C.muted)
    .text(`Generated ${formatDate(new Date())}`, 365, 34, { width: 185, align: 'right', lineBreak: false });
  if (title) {
    const icon = options.icon || '[S]';
    d.font('Helvetica-Bold').fontSize(8).fillColor(C.accentDark)
      .text(icon, PAGE.left, 96, { lineBreak: false });
    d.font('Helvetica-Bold').fontSize(18).fillColor(C.ink)
      .text(title, PAGE.left + 17, 91, { width: 350, lineBreak: false });
    if (subtitle) d.font('Helvetica').fontSize(8).fillColor(C.muted)
      .text(subtitle, PAGE.left + 17, 115, { width: 470, lineBreak: false });
  }
  d.restore();
}

function drawFooter(d, pageNo) {
  d.save();
  d.rect(PAGE.left, PAGE.footerY, PAGE.width, 0.8).fill(C.border);
  d.font('Helvetica').fontSize(6.8).fillColor(C.muted)
    .text('SecureDev | Security Assessment Report', PAGE.left, PAGE.footerY + 9, { width: 250, lineBreak: false });
  d.text(`Page ${pageNo} of 6`, PAGE.left + 390, PAGE.footerY + 9, { width: 121, align: 'right', lineBreak: false });
  d.restore();
}

function drawLogo(d, x, y) {
  const box = 30;
  d.roundedRect(x, y, box, box, 8).fill(C.accent);
  d.font('Helvetica-Bold').fontSize(15).fillColor(C.white)
    .text('OK', x + 8, y + 6, { width: 14, align: 'center', lineBreak: false });
  const textX = x + 39;
  d.font('Helvetica-Bold').fontSize(16).fillColor(C.ink).text('Secure', textX, y + 5, { lineBreak: false });
  const secureW = d.widthOfString('Secure');
  d.font('Helvetica-Bold').fontSize(16).fillColor(C.accentDark).text('Dev', textX + secureW, y + 5, { lineBreak: false });
  d.font('Helvetica').fontSize(6.5).fillColor(C.muted)
    .text('Application security made easier to understand', textX, y + 23, { width: 210, lineBreak: false });
}

function drawPage1(pages, scan, project) {
  const p = pages.startPage('Security Assessment Report', 'A clear summary of your application security posture.', { icon: '[R]' });
  const d = p.doc;
  const y = 145;
  text(d, `Project: ${project?.name || 'Unknown project'}`, PAGE.left, y, 300, 'Helvetica-Bold', 9.5, C.ink, 0);
  text(d, `Scan completed: ${formatDate(scan.completedAt)}`, PAGE.left, y + 16, 300, 'Helvetica', 8, C.muted, 0);
  if (scan.durationMs) text(d, `Scan duration: ${formatDuration(scan.durationMs)}`, PAGE.left, y + 30, 300, 'Helvetica', 8, C.muted, 0);

  const heroY = 190;
  drawScoreHero(d, scan, heroY);
  const findings = scan.findings || [];
  const counts = severityCounts(findings);
  drawMetricRow(d, heroY + 133, [
    ['!', String(findings.length), 'Total Issues', C.red, C.redText],
    ['!', String(counts.critical + counts.high), 'Critical / High', C.red, C.redText],
    ['OK', `${successfulEngines(scan)}/3`, 'Security Engines', C.green, C.greenText],
  ]);
  sectionTitle(d, 'Executive Summary', heroY + 220, 'The most important result in plain language.');
  drawCallout(d, PAGE.left, heroY + 255, PAGE.width, 72, 'What the results mean', buildExecutiveSummary(scan), C.tealSoft, C.accentDark);
  drawMiniGuide(d, heroY + 344, scan);
}

function drawScoreHero(d, scan, y) {
  const score = Number.isFinite(Number(scan.finalScore)) ? Number(scan.finalScore).toFixed(1) : 'N/A';
  const risk = scan.riskBand || 'Risk level unavailable';
  d.roundedRect(PAGE.left, y, PAGE.width, 116, 10).fill('#eef4f8').stroke(C.border);
  d.font('Helvetica-Bold').fontSize(8).fillColor(C.muted).text('OVERALL SECURITY SCORE', PAGE.left + 20, y + 14, { lineBreak: false });
  d.font('Helvetica-Bold').fontSize(38).fillColor(C.ink).text(score, PAGE.left + 20, y + 35, { lineBreak: false });
  const scoreW = d.widthOfString(score);
  d.font('Helvetica').fontSize(10).fillColor(C.muted).text('/ 100', PAGE.left + 28 + scoreW, y + 57, { lineBreak: false });
  d.roundedRect(PAGE.left + 205, y + 18, 112, 24, 7).fill(riskFill(risk));
  d.font('Helvetica-Bold').fontSize(9).fillColor(riskText(risk))
    .text(risk.toUpperCase(), PAGE.left + 205, y + 26, { width: 112, align: 'center', lineBreak: false });
  d.font('Helvetica-Bold').fontSize(12).fillColor(C.ink).text('Security posture', PAGE.left + 205, y + 53, { lineBreak: false });
  text(d, riskMeaning(risk), PAGE.left + 205, y + 71, 285, 'Helvetica', 7.8, C.text, 2);
}

function drawMetricRow(d, y, items) {
  const gap = 9, w = (PAGE.width - gap * 2) / 3;
  items.forEach((m, i) => {
    const x = PAGE.left + i * (w + gap);
    d.roundedRect(x, y, w, 62, 8).fill(m[3]).stroke(C.border);
    d.font('Helvetica-Bold').fontSize(12).fillColor(m[4]).text(m[0], x + 10, y + 10, { lineBreak: false });
    d.font('Helvetica-Bold').fontSize(17).fillColor(C.ink).text(m[1], x + 31, y + 8, { lineBreak: false });
    d.font('Helvetica-Bold').fontSize(7.5).fillColor(m[4]).text(m[2], x + 10, y + 36, { width: w - 20, lineBreak: false });
  });
}

function drawMiniGuide(d, y, scan) {
  const gap = 10, w = (PAGE.width - gap * 2) / 3, counts = severityCounts(scan.findings || []);
  const cards = [
    ['What is Working Well', 'No exposed secrets were detected. Authentication and configuration checks completed successfully.', C.green, C.greenText],
    ['Needs Attention', `${counts.high + counts.critical} high-priority finding(s) plus dependency/application issues need review.`, C.orange, C.orangeText],
    ['Next Steps', 'Fix priority findings, update affected packages, then run a fresh scan to verify the changes.', C.blue, C.blueText],
  ];
  cards.forEach((c, i) => {
    const x = PAGE.left + i * (w + gap);
    d.roundedRect(x, y, w, 112, 8).fill(c[2]).stroke(C.border);
    d.font('Helvetica-Bold').fontSize(8.5).fillColor(c[3]).text(c[0], x + 11, y + 12, { width: w - 22, lineBreak: false });
    text(d, c[1], x + 11, y + 34, w - 22, 'Helvetica', 7.4, C.text, 2);
  });
}

function drawPage2(pages, scan) {
  const p = pages.startPage('Security Overview', 'Score breakdown and detailed analysis of security checks.', { icon: '[O]' });
  const d = p.doc;
  let y = 143;
  sectionTitle(d, 'Security Area Breakdown', y, 'Each area contributes a defined weight to the overall score.');
  y += 35;
  y = drawScoreTable(d, scan, y);
  sectionTitle(d, 'Why These Scores Matter', y + 22, 'The scores help show where attention is needed first.');
  drawCallout(d, PAGE.left, y + 56, 247, 86, 'Dependency Security', 'This area has the highest weight at 30%. Known package vulnerabilities can introduce risk into otherwise secure application code.', C.blue, C.blueText);
  drawCallout(d, PAGE.left + 265, y + 56, 246, 86, 'Application Security', 'This area reflects code-level risks such as unsafe input handling and sensitive response data.', C.tealSoft, C.accentDark);
  sectionTitle(d, 'Assessment Status', y + 163, 'Coverage and scanner status for this assessment.');
  drawStatusTable(d, scan, y + 196);
}

function drawScoreTable(d, scan, y) {
  const cols = [118, 184, 54, 75, 80], x = PAGE.left, headerH = 26, rowH = 48;
  const headers = ['Security Area', 'What it checks', 'Weight', 'Score', 'Status'];
  let cx = x;
  d.roundedRect(x, y, PAGE.width, headerH, 5).fill(C.slate2);
  headers.forEach((h, i) => { text(d, h, cx + 7, y + 8, cols[i] - 14, 'Helvetica-Bold', 7.2, C.ink, 0); cx += cols[i]; });
  y += headerH;

  const sub = scan.subScores || {};
  SUBSCORES.forEach(([key, label, explanation, weight], idx) => {
    cx = x;
    const score = Number.isFinite(Number(sub[key])) ? Math.round(Number(sub[key])) : null;
    const status = score === null ? 'Unknown' : score >= 80 ? 'Good' : score >= 60 ? 'Review' : 'Needs Attention';
    d.rect(x, y, PAGE.width, rowH).fill(idx % 2 ? C.white : '#fbfdff').stroke(C.border);
    text(d, label, cx + 7, y + 9, cols[0] - 14, 'Helvetica-Bold', 7.5, C.ink, 1);
    cx += cols[0];
    text(d, explanation, cx + 7, y + 9, cols[1] - 14, 'Helvetica', 6.9, C.text, 1.2);
    cx += cols[1];
    text(d, `${weight}%`, cx + 7, y + 20, cols[2] - 14, 'Helvetica-Bold', 7.5, C.ink, 0, 'center');
    cx += cols[2];
    const scoreBg = score === null ? C.slate2 : score >= 80 ? C.green : score >= 60 ? C.amber : C.red;
    const scoreColor = score === null ? C.muted : score >= 80 ? C.greenText : score >= 60 ? C.amberText : C.redText;
    d.roundedRect(cx + 5, y + 12, cols[3] - 10, 24, 6).fill(scoreBg);
    text(d, score === null ? 'N/A' : `${score} / 100`, cx + 5, y + 20, cols[3] - 10, 'Helvetica-Bold', 7.2, scoreColor, 0, 'center');
    cx += cols[3];
    text(d, status, cx + 5, y + 16, cols[4] - 10, 'Helvetica-Bold', 6.4, status === 'Good' ? C.greenText : status === 'Review' ? C.amberText : C.redText, 1, 'center');
    y += rowH;
  });
  return y + 12;
}

function drawStatusTable(d, scan, y) {
  const rows = [
    ['Overall Status', scan.assessmentStatus === 'complete' ? 'Complete' : 'Incomplete'],
    ['Checks Completed', `${successfulEngines(scan)} / 3`],
    ['Scan Duration', scan.durationMs ? formatDuration(scan.durationMs) : 'Unavailable'],
    ['Scan Engines', 'npm audit / Secret scanner / Semgrep'],
  ];
  const h = rows.length * 26 + 12;
  d.roundedRect(PAGE.left, y, PAGE.width, h, 8).fill(C.white).stroke(C.border);
  rows.forEach((r, i) => {
    const ry = y + 6 + i * 26;
    if (i) d.rect(PAGE.left + 10, ry - 2, PAGE.width - 20, 0.7).fill(C.border);
    text(d, r[0], PAGE.left + 13, ry + 6, 120, 'Helvetica-Bold', 7.2, C.muted, 0);
    text(d, r[1], PAGE.left + 145, ry + 6, PAGE.width - 158, 'Helvetica-Bold', 7.5, C.ink, 0);
  });
}

function drawPage3(pages, scan) {
  const p = pages.startPage('Security Checks Performed', 'These tools work together to give one comprehensive assessment.', { icon: '[C]' });
  const d = p.doc;
  let y = 143;
  y = drawEngineTable(d, scan, y);
  sectionTitle(d, 'Key Takeaways', y + 22, 'What a non-technical reader should take away from the scan.');
  y += 58;

  const findings = scan.findings || [], counts = severityCounts(findings);
  const cards = [
    ['What is Working Well', 'No exposed secrets were detected. Authentication and configuration checks completed successfully.', C.green, C.greenText],
    ['Needs Attention', `${counts.high + counts.critical} high-priority code finding(s) were detected. Dependency and application-security scores also need review.`, C.orange, C.orangeText],
    ['Next Steps', 'Address high-priority issues, update vulnerable dependencies, then re-run the scan and compare the new score.', C.blue, C.blueText],
  ];
  const gap = 10, w = (PAGE.width - gap * 2) / 3;
  cards.forEach((c, i) => {
    const x = PAGE.left + i * (w + gap);
    d.roundedRect(x, y, w, 110, 9).fill(c[2]).stroke(C.border);
    text(d, c[0], x + 12, y + 13, w - 24, 'Helvetica-Bold', 8.5, c[3], 0);
    text(d, c[1], x + 12, y + 38, w - 24, 'Helvetica', 7.7, C.text, 2);
  });
  drawQuote(d, y + 126, 'Security is not a one-time check. Regular scans help keep application changes visible and manageable.');
  drawScanCoverage(d, scan, y + 188);
}

function drawEngineTable(d, scan, y) {
  sectionTitle(d, 'Scanner Coverage', y, 'Status and purpose of each security engine.');
  y += 34;
  const cols = [100, 72, 178, 161], headers = ['Engine', 'Status', 'Purpose', 'Result'];
  const rows = [
    ['npm audit', scan.engineStatus?.npmAudit, 'Checks project dependencies for known vulnerabilities.', dependencyResult(scan)],
    ['Secret scanner', scan.engineStatus?.secretScanner, 'Looks for exposed credentials and secret-like values.', secretResult(scan)],
    ['Semgrep', scan.engineStatus?.semgrep, 'Checks source code for security patterns.', semgrepResult(scan)],
  ];
  d.roundedRect(PAGE.left, y, PAGE.width, 25, 4).fill(C.slate2);
  let cx = PAGE.left;
  headers.forEach((h, i) => { text(d, h, cx + 7, y + 8, cols[i] - 14, 'Helvetica-Bold', 7.2, C.ink, 0); cx += cols[i]; });
  y += 25;
  rows.forEach((r, idx) => {
    const h = 54;
    cx = PAGE.left;
    d.rect(PAGE.left, y, PAGE.width, h).fill(idx % 2 ? C.white : '#fbfdff').stroke(C.border);
    text(d, r[0], cx + 7, y + 10, cols[0] - 14, 'Helvetica-Bold', 7.6, C.ink, 0);
    cx += cols[0];
    const ok = r[1] === 'success';
    d.roundedRect(cx + 6, y + 15, cols[1] - 12, 20, 6).fill(ok ? C.green : C.red);
    text(d, ok ? 'Success' : (r[1] || 'Unknown'), cx + 6, y + 21, cols[1] - 12, 'Helvetica-Bold', 6.8, ok ? C.greenText : C.redText, 0, 'center');
    cx += cols[1];
    text(d, r[2], cx + 7, y + 8, cols[2] - 14, 'Helvetica', 7.1, C.text, 1.5);
    cx += cols[2];
    text(d, r[3], cx + 7, y + 8, cols[3] - 14, 'Helvetica', 7.1, C.text, 1.5);
    y += h;
  });
  return y;
}

function drawQuote(d, y, body) {
  d.roundedRect(PAGE.left, y, PAGE.width, 48, 8).fill(C.blue).stroke(C.border);
  d.font('Helvetica-Bold').fontSize(20).fillColor(C.blueText).text('"', PAGE.left + 12, y + 9, { lineBreak: false });
  text(d, body, PAGE.left + 35, y + 11, PAGE.width - 50, 'Helvetica', 8, C.text, 2);
}

function drawScanCoverage(d, scan, y) {
  sectionTitle(d, 'Assessment Snapshot', y, 'A quick view of coverage, timing and issue distribution.');
  y += 35;
  const counts = severityCounts(scan.findings || []);
  const cells = [
    ['Assessment', scan.assessmentStatus === 'complete' ? 'Complete' : 'Incomplete'], ['Duration', scan.durationMs ? formatDuration(scan.durationMs) : 'Unavailable'],
    ['Critical', String(counts.critical)], ['High', String(counts.high)], ['Medium', String(counts.medium)], ['Low', String(counts.low)],
  ];
  const gap = 8, w = (PAGE.width - gap * 2) / 3, h = 42;
  cells.forEach((c, i) => {
    const row = Math.floor(i / 3), col = i % 3, x = PAGE.left + col * (w + gap), yy = y + row * (h + gap);
    d.roundedRect(x, yy, w, h, 8).fill(C.white).stroke(C.border);
    text(d, c[0], x + 10, yy + 8, w - 20, 'Helvetica-Bold', 6.7, C.muted, 0);
    text(d, c[1], x + 10, yy + 22, w - 20, 'Helvetica-Bold', 10, C.ink, 0);
  });
}

function drawPage4(pages, scan) {
  const p = pages.startPage('Findings and Remediation', 'Detailed high-priority findings with plain-language explanations and actions.', { icon: '!' });
  const d = p.doc, findings = sortedFindings(scan.findings || []);
  const high = findings.filter(f => ['critical', 'high'].includes(String(f.severity || '').toLowerCase()));
  let y = 143;
  drawPriorityBanner(d, y, 'HIGH PRIORITY FINDINGS', `${high.length}`, 'Should be addressed before release where the affected code is reachable.');
  y += 42;
  if (!high.length) {
    drawCallout(d, PAGE.left, y, PAGE.width, 90, 'No Critical or High findings', 'The completed scan did not report a Critical or High severity finding. Continue with the Medium and Low findings on the next page.', C.green, C.greenText);
    return;
  }
  high.slice(0, 3).forEach((finding, index) => { y += drawHighFindingCard(d, finding, index + 1, y) + 10; });
  if (high.length > 3) drawCallout(d, PAGE.left, y, PAGE.width, 54, 'Additional high-priority findings', `${high.length - 3} additional Critical/High finding(s) are listed in the continuation section.`, C.red, C.redText);
}

function drawHighFindingCard(d, finding, number, y) {
  const severity = String(finding.severity || 'high').toLowerCase(), [sevColor, sevBg] = SEV[severity] || SEV.high;
  const title = finding.title || 'Security finding';
  const description = finding.description || 'The scanner detected a security-related condition that needs review.';
  const location = finding.file ? `${finding.file}${finding.line ? ` (Line ${finding.line})` : ''}` : 'Location not provided';
  const category = finding.category || 'other';
  const simple = plainLanguage(title, description, category);
  const action = finding.remediation || CATEGORY_ACTIONS[category] || 'Review the affected code, apply the appropriate security control, and run the scan again.';
  const h = 182;

  d.roundedRect(PAGE.left, y, PAGE.width, h, 9).fill(C.white).stroke(C.border);
  d.roundedRect(PAGE.left, y, 5, h, 3).fill(sevColor);
  d.roundedRect(PAGE.left + 14, y + 12, 24, 24, 7).fill(sevColor);
  text(d, String(number), PAGE.left + 14, y + 19, 24, 'Helvetica-Bold', 9, C.white, 0, 'center');
  text(d, title, PAGE.left + 48, y + 12, 350, 'Helvetica-Bold', 10, C.ink, 1.5);
  d.roundedRect(PAGE.left + 425, y + 12, 55, 20, 6).fill(sevBg);
  text(d, severity.toUpperCase(), PAGE.left + 425, y + 18, 55, 'Helvetica-Bold', 6.5, sevColor, 0, 'center');

  let fy = y + 48;
  fy = findingField(d, 'WHAT WAS FOUND', description, fy, 8);
  fy = findingField(d, 'WHERE', location, fy + 5, 7.3);
  fy = findingField(d, 'IN SIMPLE TERMS', simple, fy + 5, 8);
  fy = findingField(d, 'WHY IT MATTERS', whyItMatters(severity), fy + 5, 8);
  findingField(d, 'RECOMMENDED ACTION', action, fy + 5, 8);
  return h;
}

function drawPage5(pages, scan) {
  const p = pages.startPage('Findings and Remediation (Continued)', 'Medium and lower-priority findings with practical next steps.', { icon: '!' });
  const d = p.doc, findings = sortedFindings(scan.findings || []);
  const medium = findings.filter(f => !['critical', 'high'].includes(String(f.severity || '').toLowerCase()));
  let y = 143;
  drawPriorityBanner(d, y, 'MEDIUM / LOWER PRIORITY FINDINGS', String(medium.length), 'Review as part of normal security maintenance.');
  y += 45;
  if (!medium.length) {
    drawCallout(d, PAGE.left, y, PAGE.width, 90, 'No additional findings', 'There are no Medium or Low findings to display for this assessment.', C.green, C.greenText);
    return;
  }

  const cols = [24, 145, 165, 177], headers = ['#', 'Finding', 'What it means', 'Recommended action'];
  d.roundedRect(PAGE.left, y, PAGE.width, 27, 4).fill(C.slate2);
  let cx = PAGE.left;
  headers.forEach((h, i) => { text(d, h, cx + 6, y + 9, cols[i] - 12, 'Helvetica-Bold', 7, C.ink, 0); cx += cols[i]; });
  y += 27;

  medium.forEach((finding, idx) => {
    const severity = String(finding.severity || 'medium').toLowerCase(), category = finding.category || 'other';
    const title = finding.title || CATEGORY_LABELS[category] || 'Security finding';
    const description = finding.description || CATEGORY_EXPLANATIONS[category] || 'Security issue detected.';
    const action = finding.remediation || CATEGORY_ACTIONS[category] || 'Review the affected area and run the scan again after remediation.';
    const h = 67;
    cx = PAGE.left;
    d.rect(PAGE.left, y, PAGE.width, h).fill(idx % 2 ? C.white : '#fbfdff').stroke(C.border);
    text(d, String(idx + 1), cx + 6, y + 25, cols[0] - 12, 'Helvetica-Bold', 7.2, C.ink, 0, 'center');
    cx += cols[0];
    text(d, title, cx + 6, y + 9, cols[1] - 12, 'Helvetica-Bold', 7.1, C.ink, 1.2);
    text(d, severity.toUpperCase(), cx + 6, y + 43, cols[1] - 12, 'Helvetica-Bold', 6.1, severity === 'medium' ? C.orangeText : C.blueText, 0);
    cx += cols[1];
    text(d, description, cx + 6, y + 9, cols[2] - 12, 'Helvetica', 6.7, C.text, 1.3);
    cx += cols[2];
    text(d, action, cx + 6, y + 9, cols[3] - 12, 'Helvetica', 6.7, C.text, 1.3);
    y += h;
  });
  drawCallout(d, PAGE.left, y + 12, PAGE.width, 58, 'Remediation principle', 'Fix the root cause, not only the scanner symptom. After changes are deployed, run another scan and confirm that the finding is no longer reported.', C.blue, C.blueText);
}

function drawPage6(pages, scan) {
  const p = pages.startPage('Additional Information', 'Methodology, priority guidance and important notes.', { icon: '[I]' });
  const d = p.doc;
  let y = 143;
  sectionTitle(d, 'Priority Guide', y, 'A simple way to decide what to work on first.');
  y += 34;
  const cols = [72, 150, 166, 123], headers = ['Priority', 'Meaning', 'Why it matters', 'Suggested timing'];
  d.roundedRect(PAGE.left, y, PAGE.width, 26, 4).fill(C.slate2);
  let cx = PAGE.left;
  headers.forEach((h, i) => { text(d, h, cx + 6, y + 8, cols[i] - 12, 'Helvetica-Bold', 7, C.ink, 0); cx += cols[i]; });
  y += 26;
  [
    ['High', 'Address as soon as possible.', 'May create meaningful security exposure.', 'Before release'],
    ['Medium', 'Review as part of maintenance.', 'Can increase risk depending on context.', 'Within 30 days'],
    ['Low', 'Address when practical.', 'Useful hardening and cleanup.', 'Within 90 days'],
  ].forEach((r, i) => {
    const h = 47; cx = PAGE.left;
    d.rect(PAGE.left, y, PAGE.width, h).fill(C.white).stroke(C.border);
    const bg = i === 0 ? C.red : i === 1 ? C.orange : C.blue, tc = i === 0 ? C.redText : i === 1 ? C.orangeText : C.blueText;
    d.roundedRect(cx + 6, y + 13, 58, 21, 6).fill(bg);
    text(d, r[0], cx + 6, y + 20, 58, 'Helvetica-Bold', 6.8, tc, 0, 'center');
    cx += cols[0];
    text(d, r[1], cx + 6, y + 9, cols[1] - 12, 'Helvetica-Bold', 6.8, C.ink, 1.2);
    cx += cols[1];
    text(d, r[2], cx + 6, y + 9, cols[2] - 12, 'Helvetica', 6.8, C.text, 1.2);
    cx += cols[2];
    text(d, r[3], cx + 6, y + 9, cols[3] - 12, 'Helvetica-Bold', 6.8, C.ink, 1.2);
    y += h;
  });

  sectionTitle(d, 'Report Methodology', y + 20, 'How SecureDev turns scan results into this report.');
  y += 52;
  const steps = [
    ['1', 'Dependency scanning', 'npm audit checks third-party packages for known vulnerabilities.'],
    ['2', 'Secret detection', 'The secret scanner looks for credentials and sensitive values in source files.'],
    ['3', 'Static code analysis', 'Semgrep checks source code against security rules and patterns.'],
    ['4', 'Result normalization', 'Findings are grouped and duplicates are merged before scoring.'],
    ['5', 'Weighted scoring', 'The five security areas are combined using the configured weights.'],
  ];
  steps.forEach(s => {
    d.roundedRect(PAGE.left, y, 248, 43, 7).fill(C.white).stroke(C.border);
    d.roundedRect(PAGE.left + 10, y + 10, 23, 23, 7).fill(C.blue);
    text(d, s[0], PAGE.left + 10, y + 17, 23, 'Helvetica-Bold', 7, C.blueText, 0, 'center');
    text(d, s[1], PAGE.left + 44, y + 7, 190, 'Helvetica-Bold', 7.1, C.ink, 0);
    text(d, s[2], PAGE.left + 44, y + 20, 190, 'Helvetica', 6.5, C.text, 1.1);
    y += 49;
  });

  drawCallout(d, PAGE.left + 261, 476, 246, 90, 'Assessment Limitations',
    scan.assessmentStatus === 'complete'
      ? 'Results are based on automated scanning tools. Some vulnerabilities require manual review, business context, or runtime testing. A completed assessment does not prove complete security.'
      : 'This assessment is incomplete. The available findings may be useful, but the score should not be treated as a complete representation of the application security posture.',
    C.tealSoft, C.accentDark);
  drawCallout(d, PAGE.left + 261, 578, 246, 78, 'Final Next Step',
    'Resolve the highest-priority findings, update vulnerable dependencies, run a fresh scan, and use the new report to verify improvement.',
    C.blue, C.blueText);
  drawQuote(d, 690, 'A more secure application builds trust and protects the people who use it.');
}

function sectionTitle(d, title, y, subtitle) {
  d.font('Helvetica-Bold').fontSize(13).fillColor(C.ink).text(title, PAGE.left, y, { lineBreak: false });
  if (subtitle) d.font('Helvetica').fontSize(7.6).fillColor(C.muted).text(subtitle, PAGE.left, y + 19, { width: PAGE.width, lineBreak: false });
}
function drawPriorityBanner(d, y, title, count, subtitle) {
  d.roundedRect(PAGE.left, y, PAGE.width, 30, 7).fill(C.red);
  d.font('Helvetica-Bold').fontSize(8.2).fillColor(C.redText).text(title, PAGE.left + 12, y + 10, { lineBreak: false });
  d.roundedRect(PAGE.left + 425, y + 5, 58, 20, 6).fill(C.white);
  text(d, count, PAGE.left + 425, y + 11, 58, 'Helvetica-Bold', 7, C.redText, 0, 'center');
  d.font('Helvetica').fontSize(6.5).fillColor(C.redText).text(subtitle, PAGE.left + 200, y + 11, { width: 210, align: 'right', lineBreak: false });
}
function drawCallout(d, x, y, w, h, title, body, fill, titleColor) {
  d.roundedRect(x, y, w, h, 8).fill(fill).stroke(C.border);
  text(d, title, x + 12, y + 12, w - 24, 'Helvetica-Bold', 8, titleColor, 0);
  text(d, body, x + 12, y + 31, w - 24, 'Helvetica', 7.2, C.text, 1.7);
}
function findingField(d, label, body, y, size) {
  text(d, label, PAGE.left + 14, y, 112, 'Helvetica-Bold', 6.2, C.muted, 0);
  return text(d, body, PAGE.left + 127, y - 1, PAGE.width - 145, 'Helvetica', size, C.text, 1.2);
}
function text(d, value, x, y, width, font, size, color, lineGap = 0, align = 'left') {
  d.font(font).fontSize(size).fillColor(color);
  d.text(String(value ?? ''), x, y, { width, lineGap, align });
  return y + height(d, value, width, size, lineGap);
}
function height(d, value, width, size, lineGap = 0) {
  return d.heightOfString(String(value ?? ''), { width, font: d._font ? d._font.name : 'Helvetica', size, lineGap });
}
function sortedFindings(findings) {
  return [...findings].sort((a, b) => (SEVERITY_ORDER[String(a.severity || 'low').toLowerCase()] ?? 99) - (SEVERITY_ORDER[String(b.severity || 'low').toLowerCase()] ?? 99));
}
function plainLanguage(title, description, category) {
  const t = `${title} ${description}`.toLowerCase();
  if (category === 'vulnerableDependencies' || t.includes('dependency') || t.includes('package')) return 'A third-party package used by the application has a security concern. An attacker could potentially abuse that weakness through functionality that uses the affected package.';
  if (category === 'sensitiveDataExposure' || t.includes('sensitive field')) return 'The application may send private information in a response. Someone who can access that response could see information that was not intended to be exposed.';
  if (category === 'injectionFlaws' || t.includes('injection') || t.includes('gcm-no-tag-length')) return 'A security-sensitive operation is missing an expected protection. An attacker may be able to influence the operation or bypass an intended security check.';
  return 'The scanner detected a pattern that can create security risk. The affected code should be reviewed and protected according to the recommended action.';
}
function buildExecutiveSummary(scan) {
  const findings = scan.findings || [], counts = severityCounts(findings);
  if (scan.assessmentStatus !== 'complete') return 'The assessment is incomplete. The findings shown in this report are useful for review, but the score should not be treated as a complete security picture until all configured checks finish successfully.';
  if (!findings.length) return 'The configured security checks completed without reporting a finding. Continue regular scanning and dependency maintenance because automated checks cannot prove complete security.';
  return `The assessment identified ${findings.length} security issue${findings.length === 1 ? '' : 's'}, including ${counts.critical + counts.high} Critical/High priority issue${counts.critical + counts.high === 1 ? '' : 's'}. Authentication, secrets detection and configuration checks completed successfully, while dependency and application-security areas need attention.`;
}
function riskMeaning(risk) {
  const t = String(risk || '').toLowerCase();
  if (t.includes('low')) return 'Few security concerns were detected by the completed checks. Continue regular scanning and maintenance.';
  if (t.includes('medium')) return 'The scan found security concerns that should be reviewed and addressed. The score summarizes the checks that completed.';
  if (t.includes('high')) return 'The scan found important security concerns that should be addressed promptly, especially Critical and High findings.';
  if (t.includes('critical')) return 'The scan found serious security concerns that require prompt attention before relying on affected functionality.';
  return 'Review the findings and scanner coverage before treating this assessment as a complete security picture.';
}
function whyItMatters(s) {
  if (s === 'critical') return 'This is a critical security concern and should be addressed before release when the affected code is reachable.';
  if (s === 'high') return 'This is a significant security concern and should normally be addressed before release when the affected code is reachable.';
  if (s === 'medium') return 'This is a moderate security concern. Review and fix it as part of normal security maintenance.';
  return 'This is a lower-severity signal. Review it in context and address it when practical.';
}
function severityCounts(findings) {
  return findings.reduce((a, f) => { const s = String(f.severity || 'low').toLowerCase(); a[s] = (a[s] || 0) + 1; return a; }, { critical: 0, high: 0, medium: 0, low: 0 });
}
function successfulEngines(scan) { return Object.values(scan.engineStatus || {}).filter(v => v === 'success').length; }
function riskFill(risk) { const t = String(risk || '').toLowerCase(); if (t.includes('critical') || t.includes('high')) return C.red; if (t.includes('medium')) return C.orange; return C.green; }
function riskText(risk) { const t = String(risk || '').toLowerCase(); if (t.includes('critical') || t.includes('high')) return C.redText; if (t.includes('medium')) return C.orangeText; return C.greenText; }
function dependencyResult(scan) { const n = (scan.findings || []).filter(f => f.category === 'vulnerableDependencies').length; return n ? `${n} dependency finding${n === 1 ? '' : 's'} detected.` : 'No dependency findings reported.'; }
function secretResult(scan) { const n = (scan.findings || []).filter(f => f.category === 'hardcodedSecrets').length; return n ? `${n} secret-related finding${n === 1 ? '' : 's'} detected.` : 'No exposed secrets detected.'; }
function semgrepResult(scan) { const n = (scan.findings || []).filter(f => f.engine === 'semgrep').length; return n ? `${n} source-code finding${n === 1 ? '' : 's'} detected.` : 'No Semgrep findings reported.'; }
function formatDuration(ms) { const s = Math.max(0, Math.round(Number(ms) / 1000)); return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`; }
function formatDate(v) { if (!v) return 'Unavailable'; const d = new Date(v); return Number.isNaN(d.getTime()) ? 'Unavailable' : d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }); }

module.exports = { generateScanPdf };
