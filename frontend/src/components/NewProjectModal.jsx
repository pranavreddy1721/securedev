import { useState } from 'react';
import { X, Upload, Github } from 'lucide-react';
import client from '../api/client';

export default function NewProjectModal({ onClose, onCreated }) {
  const [tab, setTab] = useState('zip');
  const [file, setFile] = useState(null);
  const [name, setName] = useState('');
  const [repos, setRepos] = useState(null);
  const [selectedRepo, setSelectedRepo] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const MAX_MB = 25;

  async function handleZipSubmit(e) {
    e.preventDefault();
    if (!file) return setError('Please choose a .zip file');
    if (file.size > MAX_MB * 1024 * 1024) {
      return setError(`File exceeds the ${MAX_MB}MB limit. Exclude node_modules and .git before zipping.`);
    }
    setError('');
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('project', file);
      if (name) formData.append('name', name);
      const { data } = await client.post('/projects/zip', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      onCreated({ project: data.project, uploadedFilePath: data.uploadedFilePath });
    } catch (err) {
      setError(err.response?.data?.error || 'Upload failed');
    } finally {
      setLoading(false);
    }
  }

  async function loadRepos() {
    setLoading(true);
    setError('');
    try {
      const { data } = await client.get('/github/repos');
      setRepos(data.repos);
    } catch (err) {
      if (err.response?.status === 400) {
        // Not connected yet — kick off OAuth
        const { data } = await client.get('/github/connect');
        window.location.href = data.redirectUrl;
      } else {
        setError('Failed to load repositories');
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleGithubSubmit() {
    if (!selectedRepo) return setError('Select a repository');
    setLoading(true);
    setError('');
    try {
      const { data } = await client.post('/projects/github', {
        repoFullName: selectedRepo.fullName,
        repoUrl: selectedRepo.cloneUrl,
        defaultBranch: selectedRepo.defaultBranch,
      });
      onCreated({ project: data.project });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create project');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-20 flex items-center justify-center bg-black/40 px-4">
      <div className="w-full max-w-md rounded-xl border border-border dark:border-border-dark bg-surface dark:bg-surface-dark p-6 shadow-xl">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-ink dark:text-ink-dark">New project</h2>
          <button onClick={onClose} className="rounded p-1 hover:bg-panel dark:hover:bg-panel-dark">
            <X className="h-4 w-4 text-muted dark:text-muted-dark" />
          </button>
        </div>

        <div className="mt-4 flex gap-2 rounded-lg bg-panel dark:bg-panel-dark p-1">
          <TabButton active={tab === 'zip'} onClick={() => setTab('zip')} icon={Upload} label="Upload .zip" />
          <TabButton active={tab === 'github'} onClick={() => { setTab('github'); if (!repos) loadRepos(); }} icon={Github} label="GitHub repo" />
        </div>

        {error && (
          <div className="mt-4 rounded-lg border border-severity-high/30 bg-severity-high/5 px-3 py-2 text-sm text-severity-high">
            {error}
          </div>
        )}

        {tab === 'zip' ? (
          <form onSubmit={handleZipSubmit} className="mt-4 space-y-3">
            <p className="text-xs text-muted dark:text-muted-dark">
              Max {MAX_MB}MB. Exclude <code className="font-data">node_modules</code> and{' '}
              <code className="font-data">.git</code> before zipping.
            </p>
            <input
              type="text"
              placeholder="Project name (optional)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-lg border border-border dark:border-border-dark bg-surface dark:bg-surface-dark px-3 py-2 text-sm"
            />
            <input
              type="file"
              accept=".zip"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="w-full rounded-lg border border-dashed border-border dark:border-border-dark px-3 py-4 text-sm"
            />
            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-accent-500 py-2.5 text-sm font-semibold text-white hover:bg-accent-600 disabled:opacity-60"
            >
              {loading ? 'Uploading…' : 'Upload & continue'}
            </button>
          </form>
        ) : (
          <div className="mt-4 space-y-3">
            {loading && !repos && <p className="text-sm text-muted dark:text-muted-dark">Loading repositories…</p>}
            {repos && (
              <div className="max-h-64 space-y-1 overflow-y-auto">
                {repos.map((r) => (
                  <button
                    key={r.fullName}
                    onClick={() => setSelectedRepo(r)}
                    className={`block w-full rounded-lg border px-3 py-2 text-left text-sm ${
                      selectedRepo?.fullName === r.fullName
                        ? 'border-accent-500 bg-accent-50 dark:bg-accent-500/10'
                        : 'border-border dark:border-border-dark hover:bg-panel dark:hover:bg-panel-dark'
                    }`}
                  >
                    <span className="font-medium text-ink dark:text-ink-dark">{r.fullName}</span>
                    {r.language && <span className="ml-2 text-xs text-muted dark:text-muted-dark">{r.language}</span>}
                  </button>
                ))}
                {repos.length === 0 && (
                  <p className="text-sm text-muted dark:text-muted-dark">No public repositories found.</p>
                )}
              </div>
            )}
            <button
              onClick={handleGithubSubmit}
              disabled={loading || !selectedRepo}
              className="w-full rounded-lg bg-accent-500 py-2.5 text-sm font-semibold text-white hover:bg-accent-600 disabled:opacity-60"
            >
              {loading ? 'Working…' : 'Connect & continue'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function TabButton({ active, onClick, icon: Icon, label }) {
  return (
    <button
      onClick={onClick}
      className={`flex flex-1 items-center justify-center gap-1.5 rounded-md py-1.5 text-sm font-medium ${
        active ? 'bg-surface dark:bg-surface-dark text-ink dark:text-ink-dark shadow-sm' : 'text-muted dark:text-muted-dark'
      }`}
    >
      <Icon className="h-3.5 w-3.5" /> {label}
    </button>
  );
}
