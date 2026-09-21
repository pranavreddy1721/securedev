const PDFDocument = require('pdfkit');
const { HEURISTIC_CATEGORIES } = require('../config/scoring.config');

const PAGE = {
  left: 48,
  right: 48,
  top: 52,
  bottom: 64,
  width: 499,
};

const COLORS = {
  ink: '#0f172a',
  text: '#334155',
  muted: '#64748b',
  light: '#f8fafc',
  border: '#e2e8f0',
  accent: '#10b981',
  accentDark: '#047857',
  blue: '#2563eb',
  blueLight: '#eff6ff',
  greenLight: '#ecfdf5',
  amberLight: '#fffbeb',
  redLight: '#fef2f2',
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
    bufferPages: true,
    autoFirstPage: true,
    info: {
      Title: `SecureDev Security Report - ${project?.name || 'Project'}`,
      Author: 'SecureDev',
      Subject: 'Application security assessment',
    },
  });

  addPageFrame(doc);
  drawCover(doc, scan, project);

  doc.addPage();
  drawPageHeader(doc, 'Security overview', 'Score breakdown and security checks used for this assessment.');
  drawScoreBreakdown(doc, scan);
  drawEngineCoverage(doc, scan);

  doc.addPage();
  drawPageHeader(doc, 'Findings and remediation', 'Plain-language explanations of detected issues and practical next steps.');
  drawFindings(doc, scan);

  doc.addPage();
  drawPageHeader(doc, 'How SecureDev produced this report', 'A transparent summary of the scanning process, scoring model, and limitations.');
  drawMethodology(doc, scan);

  addPageNumbers(doc);
  doc.end();
  return doc;
}

function addPageFrame(doc) {
  doc.on('pageAdded', () => {
    doc.save();
    drawFrame(doc);
    doc.restore();
  });

  doc.save();
  drawFrame(doc);
  doc.restore();
}

function drawFrame(doc) {
  const bottom = doc.page.height - PAGE.bottom + 20;
  doc.strokeColor(COLORS.border).lineWidth(0.6)
    .moveTo(PAGE.left, bottom).lineTo(doc.page.width - PAGE.right, bottom).stroke();
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
  doc.moveDown(0.35);
  doc.font('Helvetica').fontSize(11).fillColor(COLORS.muted)
    .text(`Project: ${projectName}`)
    .text(`Scan completed: ${formatDate(scan.completedAt)}`);
  if (scan.durationMs) doc.text(`Scan duration: ${formatDuration(scan.durationMs)}`);

  doc.moveDown(1.25);
  drawScoreHero(doc, score, risk);

  doc.moveDown(1.1);
  sectionTitle(doc, 'Executive summary', 'A quick explanation for technical and non-technical readers.');
  const summaryText = riskMeaning(risk);
  infoBox(doc, 'What the score means', summaryText, COLORS.light, COLORS.text);

  doc.moveDown(0.7);
  sectionTitle(doc, 'At a glance', 'The most important results from this scan.');
  drawMetricGrid(doc, [
    ['Issues found', String(findings.length), 'Total findings detected'],
    ['Critical / High', String(counts.critical + counts.high), 'Needs prompt attention'],
    ['Checks completed', `${successfulEngines(scan)}/3`, 'Security engines finished'],
    ['Assessment', scan.assessmentStatus === 'complete' ? 'Complete' : 'Incomplete', 'Coverage status'],
  ]);

  doc.moveDown(0.9);
  const note = scan.assessmentStatus === 'complete'
    ? 'Start with Critical and High findings. The detailed pages explain each issue in plain language, show where it was found, and suggest what to do next.'
    : 'This assessment is incomplete. The available findings are still useful, but the overall score should not be treated as a complete assessment.';
  infoBox(doc, scan.assessmentStatus === 'complete' ? 'Recommended reading order' : 'Important notice', note,
    scan.assessmentStatus === 'complete' ? COLORS.blueLight : COLORS.amberLight,
    scan.assessmentStatus === 'complete' ? '#1d4ed8' : '#92400e');
}

function drawBrand(doc, y) {
  doc.roundedRect(PAGE.left, y, 38, 38, 9).fill(COLORS.accent);
  doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(21).text('✓', PAGE.left + 10, y + 7);
  doc.fillColor(COLORS.ink).font('Helvetica-Bold').fontSize(21).text('Secure', PAGE.left + 50, y + 3);
  doc.fillColor(COLORS.accentDark).text('Dev', PAGE.left + 113, y + 3);
  doc.font('Helvetica').fontSize(8.5).fillColor(COLORS.muted).text('Application security made easier to understand', PAGE.left + 50, y + 27);
}

function drawPageHeader(doc, title, subtitle) {
  doc.y = PAGE.top;
  drawBrand(doc, doc.y);
  doc.y += 55;
  doc.font('Helvetica-Bold').fontSize(20).fillColor(COLORS.ink).text(title);
  doc.moveDown(0.25);
  doc.font('Helvetica').fontSize(9.5).fillColor(COLORS.muted).text(subtitle, { width: PAGE.width, lineGap: 2 });
  doc.moveDown(0.8);
}

function drawScoreHero(doc, score, risk) {
  const y = doc.y;
  const h = 126;
  doc.roundedRect(PAGE.left, y, PAGE.width, h, 12).fill('#f1f5f9');
  doc.roundedRect(PAGE.left, y, 7, h, 3).fill(riskColor(risk));

  doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.muted).text('OVERALL SECURITY SCORE', PAGE.left + 22, y + 18);
  doc.font('Helvetica-Bold').fontSize(42).fillColor(COLORS.ink).text(score, PAGE.left + 22, y + 37, { width: 135 });
  doc.font('Helvetica').fontSize(11).fillColor(COLORS.muted).text('/ 100', PAGE.left + 124, y + 62);

  doc.font('Helvetica-Bold').fontSize(18).fillColor(riskColor(risk)).text(risk, PAGE.left + 190, y + 25);
  doc.font('Helvetica-Bold').fontSize(9.5).fillColor(COLORS.text).text('Risk level', PAGE.left + 190, y + 53);
  doc.font('Helvetica').fontSize(9).fillColor(COLORS.text).text(riskMeaning(risk), PAGE.left + 190, y + 69, {
    width: PAGE.width - 212,
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
    doc.roundedRect(x, y, w, 66, 8).fill('#ffffff').stroke(COLORS.border);
    doc.font('Helvetica-Bold').fontSize(15).fillColor(COLORS.ink).text(metric[1], x + 9, y + 11, { width: w - 18 });
    doc.font('Helvetica-Bold').fontSize(7.5).fillColor(COLORS.text).text(metric[0], x + 9, y + 32, { width: w - 18 });
    doc.font('Helvetica').fontSize(7).fillColor(COLORS.muted).text(metric[2], x + 9, y + 45, { width: w - 18, lineGap: 1 });
  });
  doc.y = y + 78;
}

function drawScoreBreakdown(doc, scan) {
  sectionTitle(doc, 'How the score is calculated', 'The final score is a weighted summary of five security areas. A lower sub-score means more issues were detected in that area.');
  const subScores = scan.subScores || {};

  Object.entries(SUBSCORE_INFO).forEach(([key, [label, explanation, weight]]) => {
    ensureSpace(doc, 76);
    const score = Number.isFinite(Number(subScores[key])) ? Math.round(Number(subScores[key])) : null;
    const y = doc.y;

    doc.roundedRect(PAGE.left, y, PAGE.width, 62, 9).fill('#ffffff').stroke(COLORS.border);
    doc.font('Helvetica-Bold').fontSize(10.5).fillColor(COLORS.ink).text(label, PAGE.left + 12, y + 11);
    doc.font('Helvetica').fontSize(8.2).fillColor(COLORS.muted).text(`${weight}% weight - ${explanation}`, PAGE.left + 12, y + 27, { width: 370 });
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.text).text(score === null ? 'N/A' : `${score}/100`, PAGE.left + 415, y + 13, { width: 70, align: 'right' });

    const barY = y + 45;
    doc.roundedRect(PAGE.left + 12, barY, PAGE.width - 92, 6, 3).fill('#e2e8f0');
    if (score !== null) {
      doc.roundedRect(PAGE.left + 12, barY, (PAGE.width - 92) * clamp(score, 0, 100) / 100, 6, 3).fill(scoreBarColor(score));
    }
    doc.y = y + 73;
  });

  doc.moveDown(0.2);
  infoBox(doc, 'How to interpret this section', 'The percentage beside each area is its contribution to the final score. For example, Dependency Security has a 30% weight, so dependency findings can have a substantial effect on the overall result.', COLORS.blueLight, '#1d4ed8');
}

function drawEngineCoverage(doc, scan) {
  ensureSpace(doc, 210);
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
    doc.font('Helvetica').fontSize(8.3).fillColor(COLORS.muted).text(explanation, PAGE.left + 12, y + 26, { width: 350 });
    doc.font('Helvetica-Bold').fontSize(8.5).fillColor(color).text(humanStatus(status), PAGE.left + 402, y + 19, { width: 74, align: 'right' });
    doc.y = y + 67;
  });
}

function drawFindings(doc, scan) {
  const findings = [...(scan.findings || [])].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));

  if (!findings.length) {
    infoBox(doc, 'No findings detected', 'The completed scanners did not report an issue. This does not guarantee that the application is completely secure.', COLORS.greenLight, '#166534');
    return;
  }

  const counts = severityCounts(findings);
  drawSeveritySummary(doc, counts);

  const byCategory = {};
  findings.forEach((finding) => {
    if (!byCategory[finding.category]) byCategory[finding.category] = [];
    byCategory[finding.category].push(finding);
  });

  Object.entries(byCategory).forEach(([category, categoryFindings]) => {
    ensureSpace(doc, 78);
    const label = CATEGORY_LABELS[category] || humanize(category);
    doc.roundedRect(PAGE.left, doc.y, PAGE.width, 36, 8).fill(COLORS.blueLight);
    doc.font('Helvetica-Bold').fontSize(11).fillColor(COLORS.ink).text(label, PAGE.left + 12, doc.y + 11);
    doc.font('Helvetica-Bold').fontSize(8).fillColor(COLORS.text).text(`${categoryFindings.length} issue${categoryFindings.length === 1 ? '' : 's'}`, PAGE.left + 390, doc.y + 12, { width: 90, align: 'right' });
    doc.y += 46;

    const explanation = CATEGORY_EXPLANATIONS[category] || 'A security-related issue was detected in this category.';
    infoBox(doc, 'In simple terms', explanation, '#ffffff', COLORS.text, true);

    if (HEURISTIC_CATEGORIES.includes(category)) {
      infoBox(doc, 'Pattern-based check', 'This category uses lightweight heuristics and is not exhaustive. Verify the result manually.', COLORS.amberLight, '#92400e', true);
    }

    categoryFindings.forEach((finding, index) => {
      drawFindingCard(doc, finding, category, index + 1, categoryFindings.length);
    });
  });
}

function drawSeveritySummary(doc, counts) {
  ensureSpace(doc, 88);
  sectionTitle(doc, 'Severity summary', 'Severity describes the potential impact if a finding is real and reachable.');
  const items = [
    ['Critical', counts.critical, 'Immediate attention', 'critical'],
    ['High', counts.high, 'Prompt attention', 'high'],
    ['Medium', counts.medium, 'Review and fix', 'medium'],
    ['Low', counts.low, 'Monitor / improve', 'low'],
  ];
  const gap = 9;
  const w = (PAGE.width - gap * 3) / 4;
  const y = doc.y;
  items.forEach((item, i) => {
    const x = PAGE.left + i * (w + gap);
    doc.roundedRect(x, y, w, 55, 8).fill(SEVERITY_BG[item[3]]).stroke(SEVERITY_BG[item[3]]);
    doc.font('Helvetica-Bold').fontSize(16).fillColor(SEVERITY_COLORS[item[3]]).text(String(item[1]), x + 10, y + 9);
    doc.font('Helvetica-Bold').fontSize(8).fillColor(COLORS.text).text(item[0], x + 10, y + 30);
    doc.font('Helvetica').fontSize(6.8).fillColor(COLORS.muted).text(item[2], x + 10, y + 42, { width: w - 20 });
  });
  doc.y = y + 70;
}

function drawFindingCard(doc, finding, category, index, total) {
  const title = finding.title || 'Security finding';
  const severity = String(finding.severity || 'medium').toLowerCase();
  const description = finding.description || CATEGORY_EXPLANATIONS[category] || 'A security-related issue was detected.';
  const action = CATEGORY_ACTIONS[category] || 'Review the reported code, apply the appropriate security fix, and run the scan again.';
  const technical = finding.message || finding.detail || finding.evidence || '';
  const location = formatLocation(finding.file, finding.line);
  const detectedBy = finding.engines?.length ? finding.engines.join(', ') : finding.engine;
  const ref = finding.owaspRef;

  const estimated = estimateFindingHeight(doc, finding, category);
  ensureSpace(doc, Math.min(estimated, 600));

  let y = doc.y;
  const headerHeight = 46;
  const bodyTop = y + headerHeight;

  if (bodyTop + Math.min(estimated - headerHeight, 520) > contentBottom(doc) && y > PAGE.top + 80) {
    doc.addPage();
    drawPageHeader(doc, 'Finding details', 'Continuing the detailed findings from the previous page.');
    y = doc.y;
  }

  const contentHeight = Math.max(estimated, 160);
  doc.roundedRect(PAGE.left, y, PAGE.width, contentHeight, 10).fill('#ffffff').stroke(COLORS.border);
  doc.roundedRect(PAGE.left, y, PAGE.width, headerHeight, 10).fill('#f8fafc');
  doc.rect(PAGE.left, y + headerHeight - 10, PAGE.width, 10).fill('#f8fafc');

  const badgeWidth = Math.max(55, doc.widthOfString(severity.toUpperCase()) + 18);
  doc.roundedRect(PAGE.left + 12, y + 12, badgeWidth, 20, 7).fill(SEVERITY_BG[severity] || '#f1f5f9');
  doc.font('Helvetica-Bold').fontSize(7.5).fillColor(SEVERITY_COLORS[severity] || COLORS.text).text(severity.toUpperCase(), PAGE.left + 12, y + 18, { width: badgeWidth, align: 'center' });
  doc.font('Helvetica-Bold').fontSize(10.5).fillColor(COLORS.ink).text(title, PAGE.left + 82, y + 15, { width: PAGE.width - 180 });
  doc.font('Helvetica').fontSize(7.5).fillColor(COLORS.muted).text(`${index} of ${total}`, PAGE.left + PAGE.width - 60, y + 18, { width: 48, align: 'right' });

  let cursor = bodyTop + 14;
  cursor = findingBlock(doc, 'In simple terms', description, cursor, '#f8fafc', COLORS.text);
  cursor = findingBlock(doc, 'Why it matters', severityImpact(severity), cursor, '#f8fafc', COLORS.text);
  cursor = findingBlock(doc, 'Recommended next step', action, cursor, COLORS.greenLight, '#166534');

  if (technical) cursor = findingBlock(doc, 'Technical detail', technical, cursor, '#ffffff', COLORS.text, true);

  const meta = [];
  if (location) meta.push(['Location', location]);
  if (detectedBy) meta.push(['Detected by', detectedBy]);
  if (ref) meta.push(['Reference', ref]);
  if (meta.length) {
    const metaHeight = 20 + meta.length * 14;
    doc.roundedRect(PAGE.left + 12, cursor + 5, PAGE.width - 24, metaHeight, 7).fill('#f8fafc');
    meta.forEach(([label, value], i) => {
      const rowY = cursor + 12 + i * 14;
      doc.font('Helvetica-Bold').fontSize(7.2).fillColor(COLORS.muted).text(label, PAGE.left + 22, rowY, { width: 62 });
      doc.font('Helvetica').fontSize(7.4).fillColor(COLORS.text).text(String(value), PAGE.left + 86, rowY, { width: PAGE.width - 120 });
    });
    cursor += metaHeight + 8;
  }

  doc.font('Helvetica').fontSize(7.2).fillColor(COLORS.muted).text('Review the finding in context before making changes. A scanner result is evidence to investigate, not proof that an exploit is possible.', PAGE.left + 14, cursor + 4, { width: PAGE.width - 28, lineGap: 1.5 });
  cursor += 29;

  doc.y = Math.max(cursor + 8, y + contentHeight + 10);
}

function findingBlock(doc, title, text, y, background, titleColor, technical = false) {
  const width = PAGE.width - 28;
  const bodyWidth = width - 22;
  const bodySize = technical ? 7.8 : 8.2;
  const bodyHeight = doc.heightOfString(String(text), { width: bodyWidth, font: 'Helvetica', fontSize: bodySize, lineGap: 1.5 });
  const height = Math.max(42, bodyHeight + 28);

  doc.roundedRect(PAGE.left + 14, y, width, height, 7).fill(background).stroke(background === '#ffffff' ? COLORS.border : background);
  doc.font('Helvetica-Bold').fontSize(7.8).fillColor(titleColor).text(title, PAGE.left + 24, y + 9);
  doc.font('Helvetica').fontSize(bodySize).fillColor(COLORS.text).text(String(text), PAGE.left + 24, y + 22, { width: bodyWidth, lineGap: 1.5 });
  return y + height + 8;
}

function estimateFindingHeight(doc, finding, category) {
  const parts = [
    ['In simple terms', finding.description || CATEGORY_EXPLANATIONS[category] || 'A security-related issue was detected.', 8.2],
    ['Why it matters', severityImpact(finding.severity), 8.2],
    ['Recommended next step', CATEGORY_ACTIONS[category] || 'Review the reported code, apply the appropriate security fix, and run the scan again.', 8.2],
  ];
  if (finding.message || finding.detail || finding.evidence) parts.push(['Technical detail', finding.message || finding.detail || finding.evidence, 7.8]);

  let total = 46 + 20;
  for (const [, text, size] of parts) {
    const h = doc.heightOfString(String(text), { width: PAGE.width - 50, font: 'Helvetica', fontSize: size, lineGap: 1.5 });
    total += Math.max(42, h + 28) + 8;
  }
  const meta = [finding.file || finding.line ? 1 : 0, finding.engine || (finding.engines && finding.engines.length) ? 1 : 0, finding.owaspRef ? 1 : 0].filter(Boolean).length;
  total += meta ? 28 + meta * 14 : 0;
  return total + 42;
}

function drawMethodology(doc, scan) {
  sectionTitle(doc, 'The scanning process', 'SecureDev combines scanner results into one readable assessment.');
  const steps = [
    ['1', 'Project preparation', 'SecureDev prepares the uploaded project or connected GitHub repository for scanning.'],
    ['2', 'Security checks', 'npm audit checks dependencies, the secret scanner looks for secret-like values, and Semgrep checks source-code patterns.'],
    ['3', 'Finding normalization', 'Duplicate detections are merged so the same issue is not counted repeatedly simply because multiple checks reported it.'],
    ['4', 'Scoring', 'Findings are converted into category sub-scores and combined using the configured weighted scoring model.'],
    ['5', 'Report generation', 'The findings, score, coverage, limitations, and recommended next steps are presented in this report.'],
  ];

  steps.forEach(([number, title, text]) => {
    ensureSpace(doc, 70);
    const y = doc.y;
    doc.circle(PAGE.left + 15, y + 15, 11).fill(COLORS.accent);
    doc.font('Helvetica-Bold').fontSize(8).fillColor('#ffffff').text(number, PAGE.left + 10.5, y + 11, { width: 9, align: 'center' });
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.ink).text(title, PAGE.left + 38, y + 6);
    doc.font('Helvetica').fontSize(8.4).fillColor(COLORS.text).text(text, PAGE.left + 38, y + 22, { width: PAGE.width - 50, lineGap: 1.8 });
    doc.y = y + Math.max(58, doc.heightOfString(text, { width: PAGE.width - 50, font: 'Helvetica', fontSize: 8.4, lineGap: 1.8 }) + 32);
  });

  doc.moveDown(0.4);
  sectionTitle(doc, 'Important limitation', 'What this report can and cannot tell you.');
  infoBox(doc, 'Remember', 'A clean scan does not prove that an application is completely secure. Pattern-based categories are not exhaustive, scanner results can contain false positives, and important findings should be reviewed in the context of the application.', COLORS.amberLight, '#92400e');

  if (scan.assessmentStatus === 'incomplete') {
    doc.moveDown(0.7);
    infoBox(doc, 'Assessment incomplete', scan.error || 'One or more core security checks did not complete. The available findings remain useful, but coverage is incomplete.', COLORS.redLight, '#991b1b');
  }
}

function sectionTitle(doc, title, subtitle) {
  ensureSpace(doc, 55);
  doc.font('Helvetica-Bold').fontSize(15).fillColor(COLORS.ink).text(title);
  doc.moveDown(0.2);
  doc.font('Helvetica').fontSize(8.7).fillColor(COLORS.muted).text(subtitle, { width: PAGE.width, lineGap: 1.8 });
  doc.moveDown(0.75);
}

function infoBox(doc, title, text, background, titleColor, compact = false) {
  const width = PAGE.width;
  const bodyHeight = doc.heightOfString(String(text), { width: width - 28, font: 'Helvetica', fontSize: compact ? 7.8 : 8.4, lineGap: 1.6 });
  const height = bodyHeight + (compact ? 28 : 34);
  ensureSpace(doc, height + 8);
  const y = doc.y;
  doc.roundedRect(PAGE.left, y, width, height, 8).fill(background).stroke(background === '#ffffff' ? COLORS.border : background);
  doc.font('Helvetica-Bold').fontSize(compact ? 7.7 : 8.5).fillColor(titleColor).text(title, PAGE.left + 12, y + 9);
  doc.font('Helvetica').fontSize(compact ? 7.8 : 8.4).fillColor(COLORS.text).text(String(text), PAGE.left + 12, y + (compact ? 21 : 24), { width: width - 24, lineGap: 1.6 });
  doc.y = y + height + 8;
}

function ensureSpace(doc, requiredHeight) {
  if (doc.y + requiredHeight <= contentBottom(doc)) return;
  doc.addPage();
  drawPageHeader(doc, 'Security report - continued', 'The previous page was full, so this section continues here.');
}

function contentBottom(doc) {
  return doc.page.height - PAGE.bottom;
}

function addPageNumbers(doc) {
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i += 1) {
    doc.switchToPage(i);
    const pageNumber = i - range.start + 1;
    doc.save();
    doc.font('Helvetica').fontSize(7.5).fillColor('#94a3b8')
      .text(`SecureDev Security Report  |  Page ${pageNumber} of ${range.count}`, PAGE.left, doc.page.height - 40, {
        width: PAGE.width,
        align: 'center',
      });
    doc.restore();
  }
}

function severityCounts(findings) {
  return findings.reduce((acc, finding) => {
    const severity = String(finding.severity || '').toLowerCase();
    if (acc[severity] !== undefined) acc[severity] += 1;
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
  return 'Not run';
}

function riskMeaning(risk) {
  const value = String(risk || '').toLowerCase();
  if (value.includes('critical')) return 'The scan found issues that may have a serious security impact and should be investigated immediately.';
  if (value.includes('high')) return 'The scan found important security concerns that should be reviewed and addressed promptly.';
  if (value.includes('medium')) return 'The scan found security concerns that should be reviewed and addressed. The score is a summary of the checks that completed.';
  if (value.includes('low')) return 'The scan found fewer or lower-impact concerns, but the findings should still be reviewed.';
  if (value.includes('good') || value.includes('secure')) return 'The completed checks found relatively few security concerns. Review the detailed findings and limitations before treating the result as final.';
  return 'The score summarizes the security checks that completed. Review the detailed findings and limitations before making changes.';
}

function severityImpact(severity) {
  const value = String(severity || '').toLowerCase();
  if (value === 'critical') return 'A critical issue can have a severe impact if it is reachable and exploitable. It should be investigated immediately.';
  if (value === 'high') return 'A high-severity issue can create significant security risk if the affected code is reachable. It should normally be addressed before release.';
  if (value === 'medium') return 'A medium-severity issue represents a meaningful security concern and should be reviewed and fixed as part of normal maintenance.';
  return 'A lower-severity issue may have limited impact on its own, but fixing it can improve the overall security posture.';
}

function riskColor(risk) {
  const value = String(risk || '').toLowerCase();
  if (value.includes('critical')) return SEVERITY_COLORS.critical;
  if (value.includes('high')) return SEVERITY_COLORS.high;
  if (value.includes('medium')) return SEVERITY_COLORS.medium;
  if (value.includes('low')) return SEVERITY_COLORS.low;
  return COLORS.accent;
}

function scoreBarColor(score) {
  if (score < 40) return SEVERITY_COLORS.high;
  if (score < 70) return SEVERITY_COLORS.medium;
  return COLORS.accent;
}

function formatLocation(file, line) {
  if (!file) return '';
  return line ? `${file}:${line}` : file;
}

function formatDuration(ms) {
  const value = Number(ms);
  if (!Number.isFinite(value)) return 'N/A';
  const seconds = Math.round(value / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

function formatDate(value) {
  if (!value) return 'N/A';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'N/A' : date.toLocaleString();
}

function humanize(value) {
  return String(value || 'Security issue').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

module.exports = { generateScanPdf };
