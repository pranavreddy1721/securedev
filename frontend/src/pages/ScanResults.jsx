import { useEffect, useState, useRef } from 'react';
import { Download, AlertCircle, Clock, ChevronDown, ChevronUp } from 'lucide-react';
import { useParams } from 'react-router-dom';
import client from '../api/client';
import { LoadingState, ErrorState } from '../components/AsyncStates';
import RadialGauge from '../components/RadialGauge';
import SeverityBadge from '../components/SeverityBadge';

const CATEGORY_LABELS = { vulnerableDependencies: 'Vulnerable Dependencies', hardcodedSecrets: 'Hardcoded Secrets', injectionFlaws: 'Injection Flaws', xss: 'Cross-Site Scripting (XSS)', brokenAuthentication: 'Broken Authentication', securityMisconfiguration: 'Security Misconfiguration', insecureFileUploads: 'Insecure File Uploads', brokenAccessControl: 'Broken Access Control', sensitiveDataExposure: 'Sensitive Data Exposure' };
const HEURISTIC_CATEGORIES = new Set(['insecureFileUploads', 'brokenAccessControl', 'sensitiveDataExposure']);
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SUBSCORE_LABELS = { dependency: 'Dependency Security', authentication: 'Authentication', secrets: 'Secrets Detection', owaspCompliance: 'OWASP Compliance', configuration: 'Configuration' };

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
      } catch { if (!cancelled) setError('Failed to load scan.'); }
    }
    poll(); pollRef.current = setInterval(poll, 3000);
    return () => { cancelled = true; clearInterval(pollRef.current); };
  }, [id]);

  async function handleDownloadReport() {
    if (!scan?._id || downloading) return;

    setDownloading(true);
    try {
      // Use the authenticated Axios client instead of a normal <a href>.
      // The report endpoint is protected by requireAuth, so a direct browser
      // navigation does not include the Bearer token and returns 401.
      const response = await client.get(`/scans/${scan._id}/report`, {
        responseType: 'blob',
      });

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

  if (error) return <div className="mx-auto max-w-4xl px-6 py-10"><ErrorState message={error} /></div>;
  if (!scan) return <LoadingState label="Loading scan…" />;
  if (scan.status === 'queued' || scan.status === 'running') return <div className="mx-auto max-w-xl px-6 py-24 text-center"><Clock className="mx-auto h-8 w-8 animate-pulse text-accent-500" /><h2 className="mt-4 text-lg font-semibold text-ink dark:text-ink-dark">{scan.status === 'queued' ? 'Scan queued…' : 'Scan in progress…'}</h2><p className="mt-2 text-sm text-muted dark:text-muted-dark">Running npm audit, secret scanning, and Semgrep in parallel. This usually takes 30–90 seconds.</p></div>;
  if (scan.status === 'failed') return <div className="mx-auto max-w-xl px-6 py-24"><ErrorState message={scan.error || 'Scan failed for an unknown reason.'} /></div>;

  const findingsByCategory = {};
  for (const f of scan.findings || []) { if (!findingsByCategory[f.category]) findingsByCategory[f.category] = []; findingsByCategory[f.category].push(f); }
  Object.values(findingsByCategory).forEach((arr) => arr.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]));
  const isIncomplete = scan.assessmentStatus === 'incomplete';

  return <div className="mx-auto max-w-4xl px-6 py-10">
    <div className="flex items-start justify-between"><div><h1 className="text-2xl font-bold text-ink dark:text-ink-dark">Scan results</h1><p className="mt-1 text-sm text-muted dark:text-muted-dark">Completed {scan.completedAt ? new Date(scan.completedAt).toLocaleString() : ''}</p></div><button type="button" onClick={handleDownloadReport} disabled={downloading} className="flex items-center gap-1.5 rounded-lg border border-border dark:border-border-dark px-4 py-2 text-sm font-medium text-ink dark:text-ink-dark hover:bg-panel dark:hover:bg-panel-dark disabled:cursor-not-allowed disabled:opacity-60"><Download className="h-4 w-4" /> {downloading ? 'Preparing PDF…' : 'Download PDF'}</button></div>
    {isIncomplete ? <div className="mt-8 rounded-xl border border-severity-high/30 bg-severity-high/5 p-5"><div className="flex items-start gap-3"><AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-severity-high" /><div><h2 className="font-semibold text-ink dark:text-ink-dark">Assessment incomplete</h2><p className="mt-1 text-sm text-muted dark:text-muted-dark">{scan.error || 'A core security engine did not complete. Findings are shown below, but a comprehensive security score was not generated.'}</p></div></div></div> : <div className="mt-8 flex flex-col items-center gap-8 rounded-xl border border-border dark:border-border-dark bg-panel dark:bg-panel-dark p-8 sm:flex-row sm:justify-around"><RadialGauge score={scan.finalScore} size={200} strokeWidth={14} /><div className="grid w-full max-w-xs gap-3">{Object.entries(scan.subScores || {}).map(([key, val]) => <div key={key}><div className="mb-1 flex justify-between text-xs text-muted dark:text-muted-dark"><span>{SUBSCORE_LABELS[key]}</span><span className="font-medium text-ink dark:text-ink-dark">{Math.round(val)}</span></div><div className="h-1.5 w-full rounded-full bg-border dark:bg-border-dark"><div className="h-1.5 rounded-full bg-accent-500" style={{ width: `${Math.min(100, val)}%` }} /></div></div>)}</div></div>}
    <div className="mt-6 flex flex-wrap gap-3 text-xs text-muted dark:text-muted-dark"><EngineChip label="npm audit" status={scan.engineStatus?.npmAudit} /><EngineChip label="Secret scanner" status={scan.engineStatus?.secretScanner} /><EngineChip label="Semgrep" status={scan.engineStatus?.semgrep} /></div>
    <h2 className="mt-10 text-lg font-semibold text-ink dark:text-ink-dark">Findings by category</h2>
    {Object.keys(findingsByCategory).length === 0 && <p className="mt-4 text-sm text-muted dark:text-muted-dark">No findings detected in this scan. 🎉</p>}
    <div className="mt-4 space-y-3">{Object.entries(findingsByCategory).map(([category, findings]) => <CategorySection key={category} category={category} findings={findings} />)}</div>
  </div>;
}

function EngineChip({ label, status }) { const color = status === 'success' ? 'text-severity-low' : status === 'skipped' ? 'text-muted dark:text-muted-dark' : 'text-severity-high'; return <span className="rounded-full border border-border dark:border-border-dark px-3 py-1">{label}: <span className={color}>{status || 'unknown'}</span></span>; }

function CategorySection({ category, findings }) {
  const [open, setOpen] = useState(true);
  const isHeuristic = HEURISTIC_CATEGORIES.has(category);
  return <div className="rounded-xl border border-border dark:border-border-dark overflow-hidden">
    <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between bg-panel dark:bg-panel-dark px-4 py-3 text-left"><div className="flex items-center gap-2"><span className="font-medium text-ink dark:text-ink-dark">{CATEGORY_LABELS[category]}</span><span className="rounded-full bg-border dark:bg-border-dark px-2 py-0.5 text-xs text-muted dark:text-muted-dark">{findings.length}</span>{isHeuristic && <span className="flex items-center gap-1 text-xs text-muted dark:text-muted-dark"><AlertCircle className="h-3 w-3" /> heuristic, not exhaustive</span>}</div>{open ? <ChevronUp className="h-4 w-4 text-muted dark:text-muted-dark" /> : <ChevronDown className="h-4 w-4 text-muted dark:text-muted-dark" />}</button>
    {open && <div className="divide-y divide-border dark:divide-border-dark">{findings.map((f, idx) => <div key={idx} className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-sm font-medium text-ink dark:text-ink-dark">{f.title}</span></div>
      <p className="mt-1 text-sm text-muted dark:text-muted-dark">{f.description}</p>{f.file && <p className="mt-1 font-data text-xs text-muted dark:text-muted-dark">{f.file}{f.line ? `:${f.line}` : ''}</p>}{f.engines?.length > 1 && <p className="mt-1 text-xs text-muted dark:text-muted-dark">Detected by: {f.engines.join(', ')}</p>}
    </div>)}</div>}
  </div>;
}
