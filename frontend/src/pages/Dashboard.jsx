import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Github, Upload, Trash2, PlayCircle } from 'lucide-react';
import client from '../api/client';
import { LoadingState, EmptyState, ErrorState } from '../components/AsyncStates';
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
    try {
      const { data } = await client.get('/projects');
      setProjects(data.projects);
    } catch {
      setError('Failed to load your projects.');
    }
  }

  useEffect(() => {
    loadProjects();
  }, []);

  async function handleCreated({ project, uploadedFilePath }) {
    setShowModal(false);
    await loadProjects();
    await handleScan(project, uploadedFilePath);
  }

  async function handleScan(project, uploadedFilePath) {
    // Zip-sourced projects have no persisted source (ephemeral temp storage
    // only, per the confirmed no-S3-in-v1 decision) — re-scanning one
    // requires a fresh upload rather than a bare "scan again" click.
    if (project.source.type === 'zip' && !uploadedFilePath) {
      setError(`"${project.name}" was uploaded as a zip and isn't stored — re-upload it to scan again.`);
      setShowModal(true);
      return;
    }
    setScanningId(project._id);
    try {
      const { data } = await client.post(`/scans/project/${project._id}`, { uploadedFilePath });
      navigate(`/scans/${data.scan._id}`);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start scan');
    } finally {
      setScanningId(null);
    }
  }

  async function handleDelete(id) {
    if (!confirm('Delete this project and all its scan history?')) return;
    await client.delete(`/projects/${id}`);
    loadProjects();
  }

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ink dark:text-ink-dark">Your projects</h1>
          <p className="mt-1 text-sm text-muted dark:text-muted-dark">Upload a zip or connect a repo to get a security score.</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-1.5 rounded-lg bg-accent-500 px-4 py-2 text-sm font-semibold text-white hover:bg-accent-600"
        >
          <Plus className="h-4 w-4" /> New scan
        </button>
      </div>

      <div className="mt-8">
        {error && <ErrorState message={error} onRetry={loadProjects} />}
        {!error && !projects && <LoadingState label="Loading your projects…" />}
        {!error && projects?.length === 0 && (
          <EmptyState
            icon={Upload}
            title="No projects yet"
            description="Upload a .zip or connect a GitHub repo to run your first scan."
            action={
              <button
                onClick={() => setShowModal(true)}
                className="mt-2 rounded-lg bg-accent-500 px-4 py-2 text-sm font-semibold text-white hover:bg-accent-600"
              >
                Start your first scan
              </button>
            }
          />
        )}

        {projects && projects.length > 0 && (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {projects.map((p) => (
              <div
                key={p._id}
                className="rounded-xl border border-border dark:border-border-dark bg-panel dark:bg-panel-dark p-5"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    {p.source.type === 'github' ? (
                      <Github className="h-4 w-4 text-muted dark:text-muted-dark" />
                    ) : (
                      <Upload className="h-4 w-4 text-muted dark:text-muted-dark" />
                    )}
                    <h3 className="font-semibold text-ink dark:text-ink-dark">{p.name}</h3>
                  </div>
                  <button onClick={() => handleDelete(p._id)} className="text-muted hover:text-severity-high dark:text-muted-dark">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>

                <div className="mt-4 flex items-center justify-center">
                  {p.lastScore != null ? (
                    <RadialGauge score={p.lastScore} size={120} strokeWidth={10} />
                  ) : (
                    <div className="flex h-[120px] w-[120px] items-center justify-center rounded-full border-2 border-dashed border-border dark:border-border-dark text-xs text-muted dark:text-muted-dark">
                      No scans yet
                    </div>
                  )}
                </div>

                <div className="mt-4 flex gap-2">
                  <button
                    onClick={() => handleScan(p)}
                    disabled={scanningId === p._id}
                    className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-border dark:border-border-dark py-2 text-sm font-medium text-ink dark:text-ink-dark hover:bg-surface dark:hover:bg-surface-dark disabled:opacity-60"
                  >
                    <PlayCircle className="h-4 w-4" /> {scanningId === p._id ? 'Starting…' : 'Scan again'}
                  </button>
                  {p.lastScanId && (
                    <button
                      onClick={() => navigate(`/projects/${p._id}/history`)}
                      className="rounded-lg border border-border dark:border-border-dark px-3 py-2 text-sm text-ink dark:text-ink-dark hover:bg-surface dark:hover:bg-surface-dark"
                    >
                      History
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showModal && <NewProjectModal onClose={() => setShowModal(false)} onCreated={handleCreated} />}
    </div>
  );
}
