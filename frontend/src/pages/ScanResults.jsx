import { useEffect, useState, useRef } from 'react';
import {
  Download,
  AlertCircle,
  Clock,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  FileCode2,
  Info,
  ShieldCheck,
  Wrench,
} from 'lucide-react';
import { useParams } from 'react-router-dom';
import client from '../api/client';
import { LoadingState, ErrorState } from '../components/AsyncStates';
import RadialGauge from '../components/RadialGauge';
import SeverityBadge from '../components/SeverityBadge';

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
  hardcodedSecrets: 'A password, API key, token, or similar secret appears to be stored in the project files instead of being kept outside the source code.',
  injectionFlaws: 'User-controlled input may reach a sensitive operation without enough protection, which can allow an attacker to influence what the application does.',
  xss: 'Untrusted content may be displayed in a web page without enough protection, allowing malicious browser code to run for another user.',
  brokenAuthentication: 'The application may have a weakness in the way it verifies users or manages authenticated sessions.',
  securityMisconfiguration: 'A security-sensitive setting appears unsafe or incomplete. A wrong configuration can expose functionality that should be protected.',
  insecureFileUploads: 'Uploaded files may not be checked or stored safely enough. A malicious file could cause unexpected behavior if it is accepted or handled incorrectly.',
  brokenAccessControl: 'The application may not consistently check whether a user is allowed to access an action or resource.',
  sensitiveDataExposure: 'An API response or other output may reveal information that should remain private, such as tokens, secrets, or password-related data.',
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

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SUBSCORE_INFO = {
  dependency: ['Dependency Security', 'Third-party packages and known vulnerabilities.', '30%'],
  authentication: ['Authentication', 'Protection around user identity and access.', '20%'],
  secrets: ['Secrets Detection', 'Credentials or secret-like values in source code.', '20%'],
  owaspCompliance: ['Application Security', 'Common application security risks found in code.', '20%'],
  configuration: ['Configuration', 'Security-sensitive application configuration.', '10%'],
};

export default function ScanResults() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState('');
  const [downloading, setDownloading] = useState(false);
  const pollRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    async function poll() {
      try {
        const { data } = await client.get(`/scans/${id}`);
        if (cancelled) return;
        setScan(data.scan);
        if (['completed', 'failed'].includes(data.scan.status)) clearInterval(pollRef.current);
      } catch {
        if (!cancelled) setError('Failed to load scan.');
      }
    }
    poll();
    pollRef.current = setInterval(poll, 3000);
    return () => {
      cancelled = true;
      clearInterval(pollRef.current);
    };
  }, [id]);

  async function handleDownloadReport() {
    if (!scan?._id || downloading) return;
    setDownloading(true);
    try {
      const response = await client.get(`/scans/${scan._id}/report`, { responseType: 'blob' });
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `securedev-report-${scan._id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (downloadError) {
      console.error('Failed to download PDF report:', downloadError);
      setError('Failed to download the PDF report. Please try again.');
    } finally {
      setDownloading(false);
    }
  }

  if (error) return <div className="mx-auto max-w-5xl px-6 py-10"><ErrorState message={error} /></div>;
  if (!scan) return <LoadingState label="Loading scan…" />;
  if (scan.status === 'queued' || scan.status === 'running') {
    return <div className="mx-auto max-w-xl px-6 py-24 text-center">
      <Clock className="mx-auto h-8 w-8 animate-pulse text-accent-500" />
      <h2 className="mt-4 text-lg font-semibold text-ink dark:text-ink-dark">{scan.status === 'queued' ? 'Scan queued…' : 'Scan in progress…'}</h2>
      <p className="mt-2 text-sm text-muted dark:text-muted-dark">SecureDev is checking your project with dependency, secret, and source-code security scanners. This usually takes 30–90 seconds.</p>
    </div>;
  }
  if (scan.status === 'failed') return <div className="mx-auto max-w-xl px-6 py-24"><ErrorState message={scan.error || 'Scan failed for an unknown reason.'} /></div>;

  const findingsByCategory = {};
  for (const f of scan.findings || []) {
    if (!findingsByCategory[f.category]) findingsByCategory[f.category] = [];
    findingsByCategory[f.category].push(f);
  }
  Object.values(findingsByCategory).forEach((arr) => arr.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]));

  const findings = scan.findings || [];
  const counts = findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
  const isIncomplete = scan.assessmentStatus === 'incomplete';

  return <div className="mx-auto max-w-5xl px-6 py-10">
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <div className="flex items-center gap-2 text-accent-600 dark:text-accent-400"><ShieldCheck className="h-5 w-5" /><span className="text-xs font-bold uppercase tracking-[0.16em]">Security assessment</span></div>
        <h1 className="mt-2 text-3xl font-bold text-ink dark:text-ink-dark">Scan results</h1>
        <p className="mt-1 text-sm text-muted dark:text-muted-dark">Completed {scan.completedAt ? new Date(scan.completedAt).toLocaleString() : ''}{scan.durationMs ? ` • Duration ${formatDuration(scan.durationMs)}` : ''}</p>
      </div>
      <button type="button" onClick={handleDownloadReport} disabled={downloading} className="flex items-center justify-center gap-1.5 rounded-lg border border-border bg-white px-4 py-2 text-sm font-medium text-ink shadow-sm hover:bg-panel dark:border-border-dark dark:bg-panel-dark dark:text-ink-dark dark:hover:bg-panel-dark disabled:cursor-not-allowed disabled:opacity-60">
        <Download className="h-4 w-4" /> {downloading ? 'Preparing PDF…' : 'Download PDF report'}
      </button>
    </div>

    {isIncomplete && <div className="mt-8 rounded-xl border border-severity-high/30 bg-severity-high/5 p-5"><div className="flex items-start gap-3"><AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-severity-high" /><div><h2 className="font-semibold text-ink dark:text-ink-dark">Assessment incomplete</h2><p className="mt-1 text-sm leading-6 text-muted dark:text-muted-dark">{scan.error || 'A core security check did not complete. The findings below are still useful, but the overall score should not be treated as a complete assessment.'}</p></div></div></div>}

    {!isIncomplete && <section className="mt-8 rounded-2xl border border-border bg-panel p-6 dark:border-border-dark dark:bg-panel-dark">
      <div className="grid gap-8 lg:grid-cols-[220px_1fr] lg:items-center">
        <div className="flex justify-center"><RadialGauge score={scan.finalScore} size={190} strokeWidth={14} /></div>
        <div>
          <p className="text-xs font-bold uppercase tracking-[0.14em] text-muted dark:text-muted-dark">What your score means</p>
          <h2 className="mt-2 text-2xl font-bold text-ink dark:text-ink-dark">{scan.riskBand || 'Risk level unavailable'}</h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted dark:text-muted-dark">{riskMeaning(scan.riskBand)}</p>
          <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <SummaryCard label="Total issues" value={findings.length} />
            <SummaryCard label="Critical / High" value={counts.critical + counts.high} emphasis="high" />
            <SummaryCard label="Checks completed" value={`${Object.values(scan.engineStatus || {}).filter((s) => s === 'success').length}/3`} />
            <SummaryCard label="Assessment" value="Complete" />
          </div>
        </div>
      </div>
    </section>}

    <section className="mt-8">
      <SectionHeading title="How the score is calculated" subtitle="The final score is a weighted summary of five security areas. A lower sub-score means more issues were detected in that area." />
      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        {Object.entries(SUBSCORE_INFO).map(([key, [label, explanation, weight]]) => {
          const value = Number(scan.subScores?.[key] ?? 0);
          return <div key={key} className="rounded-xl border border-border bg-white p-4 dark:border-border-dark dark:bg-panel-dark">
            <div className="flex items-start justify-between gap-4"><div><p className="font-semibold text-ink dark:text-ink-dark">{label}</p><p className="mt-1 text-xs leading-5 text-muted dark:text-muted-dark">{explanation}</p></div><span className="rounded-full bg-panel px-2 py-1 text-xs font-semibold text-muted dark:bg-panel-dark dark:text-muted-dark">{weight}</span></div>
            <div className="mt-4 flex items-center gap-3"><div className="h-2 flex-1 rounded-full bg-border dark:bg-border-dark"><div className="h-2 rounded-full bg-accent-500" style={{ width: `${Math.min(100, Math.max(0, value))}%` }} /></div><span className="w-14 text-right text-sm font-semibold text-ink dark:text-ink-dark">{Math.round(value)}/100</span></div>
          </div>;
        })}
      </div>
    </section>

    <section className="mt-10">
      <SectionHeading title="Security checks performed" subtitle="These checks work together to give you one report instead of separate scanner outputs." />
      <div className="mt-4 grid gap-3 md:grid-cols-3">
        <EngineCard label="npm audit" status={scan.engineStatus?.npmAudit} description="Checks third-party packages for known vulnerabilities." />
        <EngineCard label="Secret scanner" status={scan.engineStatus?.secretScanner} description="Looks for credentials and secret-like values in project files." />
        <EngineCard label="Semgrep" status={scan.engineStatus?.semgrep} description="Checks source code for security-risk patterns." />
      </div>
    </section>

    <section className="mt-10">
      <SectionHeading title="Issues found" subtitle={findings.length ? 'Start with Critical and High issues. Each finding below explains the problem in plain language and what to do next.' : 'No issues were reported by the completed checks.'} />
      <div className="mt-4 space-y-3">
        {Object.entries(findingsByCategory).map(([category, categoryFindings]) => <CategorySection key={category} category={category} findings={categoryFindings} />)}
        {findings.length === 0 && <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-5 dark:border-emerald-900/40 dark:bg-emerald-950/20"><div className="flex items-start gap-3"><CheckCircle2 className="mt-0.5 h-5 w-5 text-emerald-600" /><div><h3 className="font-semibold text-emerald-900 dark:text-emerald-300">No findings detected</h3><p className="mt-1 text-sm leading-6 text-emerald-800 dark:text-emerald-400">The completed scanners did not report an issue. This does not guarantee that the application is completely secure.</p></div></div></div>}
      </div>
    </section>

    <section className="mt-10 rounded-xl border border-border bg-panel p-5 dark:border-border-dark dark:bg-panel-dark">
      <div className="flex items-start gap-3"><Info className="mt-0.5 h-5 w-5 shrink-0 text-accent-600" /><div><h2 className="font-semibold text-ink dark:text-ink-dark">How to read these results</h2><p className="mt-1 text-sm leading-6 text-muted dark:text-muted-dark">SecureDev combines the results of its security checks, removes duplicate detections, and calculates a weighted score. Pattern-based checks are useful signals but are not exhaustive. Always review important findings in the context of your application.</p></div></div>
    </section>
  </div>;
}

function SectionHeading({ title, subtitle }) {
  return <div><h2 className="text-xl font-bold text-ink dark:text-ink-dark">{title}</h2><p className="mt-1 text-sm leading-6 text-muted dark:text-muted-dark">{subtitle}</p></div>;
}

function SummaryCard({ label, value, emphasis }) {
  return <div className="rounded-lg border border-border bg-white p-3 dark:border-border-dark dark:bg-panel-dark"><p className="text-xs text-muted dark:text-muted-dark">{label}</p><p className={`mt-1 text-lg font-bold ${emphasis === 'high' ? 'text-severity-high' : 'text-ink dark:text-ink-dark'}`}>{value}</p></div>;
}

function EngineCard({ label, status, description }) {
  const success = status === 'success';
  const failed = status === 'failed';
  return <div className="rounded-xl border border-border bg-white p-4 dark:border-border-dark dark:bg-panel-dark">
    <div className="flex items-center justify-between gap-3"><div className="flex items-center gap-2"><CheckCircle2 className={`h-4 w-4 ${success ? 'text-emerald-600' : failed ? 'text-severity-high' : 'text-muted'}`} /><span className="font-semibold text-ink dark:text-ink-dark">{label}</span></div><span className={`text-xs font-semibold ${success ? 'text-emerald-600' : failed ? 'text-severity-high' : 'text-muted dark:text-muted-dark'}`}>{humanStatus(status)}</span></div>
    <p className="mt-2 text-xs leading-5 text-muted dark:text-muted-dark">{description}</p>
  </div>;
}

function CategorySection({ category, findings }) {
  const [open, setOpen] = useState(true);
  const isHeuristic = ['insecureFileUploads', 'brokenAccessControl', 'sensitiveDataExposure'].includes(category);
  return <div className="overflow-hidden rounded-xl border border-border dark:border-border-dark">
    <button type="button" onClick={() => setOpen(!open)} className="flex w-full items-center justify-between bg-panel px-4 py-3 text-left dark:bg-panel-dark">
      <div className="flex flex-wrap items-center gap-2"><span className="font-semibold text-ink dark:text-ink-dark">{CATEGORY_LABELS[category] || category}</span><span className="rounded-full bg-border px-2 py-0.5 text-xs text-muted dark:bg-border-dark dark:text-muted-dark">{findings.length}</span>{isHeuristic && <span className="flex items-center gap-1 rounded-full bg-amber-50 px-2 py-0.5 text-xs text-amber-700 dark:bg-amber-950/20 dark:text-amber-300"><AlertCircle className="h-3 w-3" /> pattern-based check</span>}</div>
      {open ? <ChevronUp className="h-4 w-4 text-muted dark:text-muted-dark" /> : <ChevronDown className="h-4 w-4 text-muted dark:text-muted-dark" />}
    </button>
    {open && <div className="divide-y divide-border dark:divide-border-dark">
      <div className="bg-white px-4 py-4 text-sm leading-6 text-muted dark:bg-panel-dark dark:text-muted-dark">{CATEGORY_EXPLANATIONS[category] || 'A security-related issue was detected in this category.'}</div>
      {isHeuristic && <div className="bg-amber-50 px-4 py-3 text-xs leading-5 text-amber-800 dark:bg-amber-950/20 dark:text-amber-300">This is a lightweight pattern-based check and is not exhaustive. Verify the result manually.</div>}
      {findings.map((f, idx) => <FindingCard key={idx} finding={f} category={category} />)}
    </div>}
  </div>;
}

function FindingCard({ finding, category }) {
  const [detailsOpen, setDetailsOpen] = useState(true);
  const technical = finding.description || 'The scanner reported an issue but did not provide additional detail.';
  const location = finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : null;
  const detectedBy = (finding.engines && finding.engines.length ? finding.engines : [finding.engine]).filter(Boolean).join(', ');

  return <article className="bg-white px-4 py-5 dark:bg-panel-dark">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={finding.severity} /><h3 className="text-sm font-semibold text-ink dark:text-ink-dark">{finding.title}</h3></div></div>
      <button type="button" onClick={() => setDetailsOpen(!detailsOpen)} className="flex items-center gap-1 text-xs font-medium text-muted hover:text-ink dark:text-muted-dark dark:hover:text-ink-dark">{detailsOpen ? 'Hide details' : 'Show details'} {detailsOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}</button>
    </div>

    {detailsOpen && <div className="mt-4 space-y-3">
      <InfoBlock icon={Info} title="In simple terms" text={CATEGORY_EXPLANATIONS[category] || technical} />
      <InfoBlock icon={AlertCircle} title="Why it matters" text={severityImpact(finding.severity)} />
      <InfoBlock icon={Wrench} title="Recommended next step" text={CATEGORY_ACTIONS[category] || 'Review the reported code, apply the appropriate security fix, and run the scan again.'} />

      <div className="rounded-lg bg-slate-50 p-3 dark:bg-slate-900/40">
        <div className="flex items-center gap-2"><FileCode2 className="h-4 w-4 text-muted dark:text-muted-dark" /><span className="text-xs font-semibold uppercase tracking-wide text-muted dark:text-muted-dark">Technical detail</span></div>
        <p className="mt-2 text-sm leading-6 text-muted dark:text-muted-dark">{technical}</p>
        <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2 text-xs text-muted dark:text-muted-dark">
          {location && <span><strong className="font-semibold text-ink dark:text-ink-dark">Location:</strong> <code className="font-data">{location}</code></span>}
          {detectedBy && <span><strong className="font-semibold text-ink dark:text-ink-dark">Detected by:</strong> {detectedBy}</span>}
          {finding.owaspRef && <span><strong className="font-semibold text-ink dark:text-ink-dark">Reference:</strong> {finding.owaspRef}</span>}
        </div>
      </div>
    </div>}
  </article>;
}

function InfoBlock({ icon: Icon, title, text }) {
  return <div className="rounded-lg border border-border bg-slate-50 p-3 dark:border-border-dark dark:bg-slate-900/30"><div className="flex items-center gap-2"><Icon className="h-4 w-4 text-accent-600" /><span className="text-xs font-semibold uppercase tracking-wide text-accent-700 dark:text-accent-400">{title}</span></div><p className="mt-2 text-sm leading-6 text-muted dark:text-muted-dark">{text}</p></div>;
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

function formatDuration(ms) {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}
