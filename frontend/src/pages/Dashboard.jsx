import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Activity, ArrowUpRight, Github, History, Plus, Radar, Trash2, Upload, Play, ShieldCheck } from 'lucide-react';
import client from '../api/client';
import { LoadingState, ErrorState } from '../components/AsyncStates';
import NewProjectModal from '../components/NewProjectModal';
import RadialGauge from '../components/RadialGauge';

export default function Dashboard() {
  const [projects, setProjects] = useState(null);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [scanningId, setScanningId] = useState(null);
  const navigate = useNavigate();

  async function loadProjects() {
    setError('');
    try { const { data } = await client.get('/projects'); setProjects(data.projects); }
    catch { setError('Failed to load your projects.'); }
  }
  useEffect(() => { loadProjects(); }, []);

  async function handleCreated({ project, uploadedFilePath }) {
    setShowModal(false);
    await loadProjects();
    await handleScan(project, uploadedFilePath);
  }
  async function handleScan(project, uploadedFilePath) {
    if (project.source.type === 'zip' && !uploadedFilePath) {
      setError(`“${project.name}” was uploaded as a zip and isn't stored — re-upload it to scan again.`);
      setShowModal(true);
      return;
    }
    setScanningId(project._id);
    try { const { data } = await client.post(`/scans/project/${project._id}`, { uploadedFilePath }); navigate(`/scans/${data.scan._id}`); }
    catch (err) { setError(err.response?.data?.error || 'Failed to start scan'); }
    finally { setScanningId(null); }
  }
  async function handleDelete(id) {
    if (!confirm('Delete this project and all its scan history?')) return;
    try { await client.delete(`/projects/${id}`); loadProjects(); } catch { setError('Failed to delete the project.'); }
  }

  const scored = projects?.filter((p) => p.lastScore != null) || [];
  const average = scored.length ? Math.round(scored.reduce((sum, p) => sum + p.lastScore, 0) / scored.length) : null;
  const attention = scored.filter((p) => p.lastScore < 60).length;

  return (
    <main className="min-h-[calc(100vh-76px)] bg-[#f5f8f8] dark:bg-[#061218]">
      <div className="mx-auto max-w-7xl px-5 py-8 lg:px-8 lg:py-10">
        <section className="relative overflow-hidden rounded-[30px] bg-[#071b20] px-7 py-8 text-white shadow-2xl sm:px-10">
          <div className="absolute right-[-100px] top-[-150px] h-[360px] w-[360px] rounded-full bg-emerald-400/15 blur-3xl" />
          <div className="relative z-10 flex flex-col justify-between gap-7 lg:flex-row lg:items-end">
            <div><div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1.5 text-xs font-bold tracking-wide text-emerald-300"><Radar className="h-3.5 w-3.5" /> SECURITY WORKSPACE</div><h1 className="mt-4 text-3xl font-black tracking-tight sm:text-4xl">Your security command center.</h1><p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">Monitor projects, launch scans and jump straight into the findings that need attention.</p></div>
            <button onClick={() => setShowModal(true)} className="inline-flex items-center justify-center gap-2 rounded-2xl bg-emerald-400 px-5 py-3 text-sm font-black text-slate-950 shadow-lg shadow-emerald-500/20 hover:bg-emerald-300"><Plus className="h-4 w-4" /> New security scan</button>
          </div>
        </section>

        <section className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Stat icon={ShieldCheck} label="Projects" value={projects?.length ?? '—'} detail="Tracked in workspace" />
          <Stat icon={Activity} label="Scored projects" value={scored.length} detail="Completed assessments" />
          <Stat icon={ArrowUpRight} label="Average score" value={average ?? '—'} detail={average != null ? 'Across scored projects' : 'Run a scan to calculate'} accent />
          <Stat icon={Radar} label="Attention needed" value={attention} detail="Projects below 60" danger={attention > 0} />
        </section>

        <div className="mt-8 flex items-end justify-between"><div><p className="text-xs font-bold uppercase tracking-[0.16em] text-emerald-600">Projects</p><h2 className="mt-1 text-2xl font-black tracking-tight text-slate-950 dark:text-white">Your security portfolio</h2></div><span className="hidden text-sm text-slate-500 sm:block dark:text-slate-400">{projects?.length || 0} project{projects?.length === 1 ? '' : 's'}</span></div>
        <div className="mt-5">
          {error && <ErrorState message={error} onRetry={loadProjects} />}
          {!error && !projects && <LoadingState label="Loading your security workspace…" />}
          {!error && projects?.length === 0 && <EmptyWorkspace onStart={() => setShowModal(true)} />}
          {projects && projects.length > 0 && <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">{projects.map((p) => <ProjectCard key={p._id} project={p} scanning={scanningId === p._id} onScan={() => handleScan(p)} onDelete={() => handleDelete(p._id)} onHistory={() => navigate(`/projects/${p._id}/history`)} onResults={() => p.lastScanId && navigate(`/scans/${p.lastScanId}`)} />)}</div>}
        </div>
      </div>
      {showModal && <NewProjectModal onClose={() => setShowModal(false)} onCreated={handleCreated} />}
    </main>
  );
}

function Stat({ icon: Icon, label, value, detail, accent, danger }) {
  const tone = danger ? 'bg-red-500/10 text-red-500' : accent ? 'bg-emerald-500/10 text-emerald-500' : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-300';
  return <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900/60"><div className={`grid h-10 w-10 place-items-center rounded-xl ${tone}`}><Icon className="h-5 w-5" /></div><div className="mt-4 text-2xl font-black text-slate-950 dark:text-white">{value}</div><div className="mt-1 text-sm font-bold text-slate-700 dark:text-slate-200">{label}</div><div className="mt-1 text-xs text-slate-400">{detail}</div></div>;
}

function ProjectCard({ project: p, scanning, onScan, onDelete, onHistory, onResults }) {
  const score = p.lastScore;
  return <article className="overflow-hidden rounded-[24px] border border-slate-200 bg-white shadow-sm transition hover:-translate-y-0.5 hover:shadow-xl dark:border-slate-800 dark:bg-slate-900/70">
    <div className="flex items-start justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-800"><div className="flex min-w-0 items-center gap-3"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">{p.source.type === 'github' ? <Github className="h-5 w-5" /> : <Upload className="h-5 w-5" />}</span><div className="min-w-0"><h3 className="truncate font-extrabold text-slate-900 dark:text-white">{p.name}</h3><p className="text-xs text-slate-400">{p.source.type === 'github' ? 'GitHub repository' : 'Uploaded project'}</p></div></div><button onClick={onDelete} className="rounded-lg p-2 text-slate-400 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-500/10" aria-label="Delete project"><Trash2 className="h-4 w-4" /></button></div>
    <div className="flex items-center gap-5 px-5 py-6"><div className="shrink-0">{score != null ? <RadialGauge score={score} size={112} strokeWidth={10} /> : <div className="grid h-28 w-28 place-items-center rounded-full border border-dashed border-slate-300 text-center text-xs font-semibold text-slate-400 dark:border-slate-700">No<br />assessment</div>}</div><div className="min-w-0 flex-1"><p className="text-xs font-bold uppercase tracking-widest text-slate-400">Latest assessment</p><p className="mt-2 text-sm font-bold text-slate-800 dark:text-slate-200">{score != null ? (score >= 80 ? 'Healthy security posture' : score >= 60 ? 'Review recommended' : 'Attention required') : 'Ready to scan'}</p><p className="mt-1 text-xs leading-5 text-slate-400">{p.lastScannedAt ? new Date(p.lastScannedAt).toLocaleString() : 'No completed scan yet'}</p></div></div>
    <div className="grid grid-cols-2 gap-2 border-t border-slate-100 p-4 dark:border-slate-800"><button onClick={onScan} disabled={scanning} className="inline-flex items-center justify-center gap-2 rounded-xl bg-slate-950 py-2.5 text-xs font-extrabold text-white hover:bg-slate-800 disabled:opacity-60 dark:bg-emerald-500 dark:text-slate-950"><Play className="h-3.5 w-3.5" />{scanning ? 'Starting…' : 'Scan again'}</button><button onClick={onResults} disabled={!p.lastScanId} className="rounded-xl border border-slate-200 py-2.5 text-xs font-bold text-slate-700 hover:border-emerald-300 disabled:opacity-40 dark:border-slate-700 dark:text-slate-200">View results</button></div>
    {p.lastScanId && <button onClick={onHistory} className="flex w-full items-center justify-center gap-2 border-t border-slate-100 py-3 text-xs font-bold text-emerald-600 hover:bg-emerald-50 dark:border-slate-800 dark:text-emerald-400 dark:hover:bg-emerald-500/5"><History className="h-3.5 w-3.5" /> Scan history</button>}
  </article>;
}

function EmptyWorkspace({ onStart }) {
  return <div className="rounded-[28px] border border-dashed border-slate-300 bg-white px-6 py-16 text-center dark:border-slate-700 dark:bg-slate-900/50"><div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl bg-emerald-500/10 text-emerald-500"><ShieldCheck className="h-8 w-8" /></div><h3 className="mt-5 text-xl font-black text-slate-950 dark:text-white">Your workspace is empty</h3><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500 dark:text-slate-400">Upload a MERN project or connect a GitHub repository to create your first security assessment.</p><button onClick={onStart} className="mt-6 rounded-xl bg-emerald-500 px-5 py-3 text-sm font-extrabold text-white hover:bg-emerald-600">Create first scan</button></div>;
}
