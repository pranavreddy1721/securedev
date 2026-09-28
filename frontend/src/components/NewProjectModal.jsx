import { useEffect, useMemo, useState } from 'react';
import { X, Upload, Github, RefreshCw, Unplug } from 'lucide-react';
import client from '../api/client';

export default function NewProjectModal({ onClose, onCreated }) {
  const [tab, setTab] = useState('zip');
  const [file, setFile] = useState(null);
  const [name, setName] = useState('');
  const [repos, setRepos] = useState([]);
  const [selectedRepo, setSelectedRepo] = useState(null);
  const [githubConnected, setGithubConnected] = useState(false);
  const [githubUsername, setGithubUsername] = useState('');
  const [repoPage, setRepoPage] = useState(1);
  const [hasNextPage, setHasNextPage] = useState(false);
  const [repoSearch, setRepoSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [checkingGithub, setCheckingGithub] = useState(false);
  const [error, setError] = useState('');

  const MAX_MB = 25;

  useEffect(() => {
    if (tab === 'github') checkGithubStatus();
  }, [tab]);

  async function checkGithubStatus() {
    setCheckingGithub(true);
    setError('');
    try {
      const { data } = await client.get('/github/status');
      setGithubConnected(data.connected);
      setGithubUsername(data.username || '');
      if (data.connected && repos.length === 0) await loadRepos(1, false);
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to check GitHub connection');
    } finally {
      setCheckingGithub(false);
    }
  }

  async function connectGitHub() {
    setLoading(true);
    setError('');
    try {
      const { data } = await client.get('/github/connect');
      window.location.href = data.redirectUrl;
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to start GitHub connection');
      setLoading(false);
    }
  }

  async function disconnectGitHub() {
    setLoading(true);
    setError('');
    try {
      await client.post('/github/disconnect');
      setGithubConnected(false);
      setGithubUsername('');
      setRepos([]);
      setSelectedRepo(null);
      setRepoPage(1);
      setHasNextPage(false);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to disconnect GitHub');
    } finally {
      setLoading(false);
    }
  }

  async function loadRepos(page = 1, append = false) {
    setLoading(true);
    setError('');
    try {
      const { data } = await client.get('/github/repos', { params: { page } });
      setRepos((current) => append ? [...current, ...data.repos] : data.repos);
      setRepoPage(data.page);
      setHasNextPage(data.hasNextPage);
    } catch (err) {
      if (err.response?.status === 400) {
        setGithubConnected(false);
        setRepos([]);
        setError('Connect your GitHub account before selecting a repository.');
      } else {
        setError(err.response?.data?.error || 'Failed to load repositories');
      }
    } finally {
      setLoading(false);
    }
  }

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

  async function handleGithubSubmit() {
    if (!selectedRepo) return setError('Select a repository');
    setLoading(true);
    setError('');
    try {
      const { data } = await client.post('/projects/github', {
        repoFullName: selectedRepo.fullName,
        defaultBranch: selectedRepo.defaultBranch,
      });
      onCreated({ project: data.project });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create project');
    } finally {
      setLoading(false);
    }
  }

  const filteredRepos = useMemo(() => {
    const q = repoSearch.trim().toLowerCase();
    if (!q) return repos;
    return repos.filter((r) => r.fullName.toLowerCase().includes(q) || (r.language || '').toLowerCase().includes(q));
  }, [repos, repoSearch]);

  return (
    <div className="fixed inset-0 z-20 flex items-center justify-center bg-black/40 px-4">
      <div className="w-full max-w-md rounded-xl border border-border dark:border-border-dark bg-surface dark:bg-surface-dark p-6 shadow-xl">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-ink dark:text-ink-dark">New project</h2>
          <button onClick={onClose} className="rounded p-1 hover:bg-panel dark:hover:bg-panel-dark" aria-label="Close">
            <X className="h-4 w-4 text-muted dark:text-muted-dark" />
          </button>
        </div>

        <div className="mt-4 flex gap-2 rounded-lg bg-panel dark:bg-panel-dark p-1">
          <TabButton active={tab === 'zip'} onClick={() => setTab('zip')} icon={Upload} label="Upload .zip" />
          <TabButton active={tab === 'github'} onClick={() => setTab('github')} icon={Github} label="GitHub repo" />
        </div>

        {error && (
          <div className="mt-4 rounded-lg border border-severity-high/30 bg-severity-high/5 px-3 py-2 text-sm text-severity-high">
            {error}
          </div>
        )}

        {tab === 'zip' ? (
          <form onSubmit={handleZipSubmit} className="mt-4 space-y-3">
            <p className="text-xs text-muted dark:text-muted-dark">
              Max {MAX_MB}MB. Exclude <code className="font-data">node_modules</code> and <code className="font-data">.git</code> before zipping.
            </p>
            <input type="text" placeholder="Project name (optional)" value={name} onChange={(e) => setName(e.target.value)} className="w-full rounded-lg border border-border dark:border-border-dark bg-surface dark:bg-surface-dark px-3 py-2 text-sm" />
            <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files?.[0] || null)} className="w-full rounded-lg border border-dashed border-border dark:border-border-dark px-3 py-4 text-sm" />
            <button type="submit" disabled={loading} className="w-full rounded-lg bg-accent-500 py-2.5 text-sm font-semibold text-white hover:bg-accent-600 disabled:opacity-60">{loading ? 'Uploading…' : 'Upload & continue'}</button>
          </form>
        ) : (
          <div className="mt-4 space-y-3">
            {checkingGithub ? (
              <p className="text-sm text-muted dark:text-muted-dark">Checking GitHub connection…</p>
            ) : !githubConnected ? (
              <div className="rounded-xl border border-border dark:border-border-dark p-4 text-center">
                <Github className="mx-auto h-8 w-8 text-muted dark:text-muted-dark" />
                <p className="mt-2 text-sm font-semibold text-ink dark:text-ink-dark">Connect your GitHub account</p>
                <p className="mt-1 text-xs leading-5 text-muted dark:text-muted-dark">SecureDev requests public repository access so you can select a repository for scanning.</p>
                <button onClick={connectGitHub} disabled={loading} className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-accent-500 py-2.5 text-sm font-semibold text-white hover:bg-accent-600 disabled:opacity-60"><Github className="h-4 w-4" />{loading ? 'Connecting…' : 'Connect GitHub'}</button>
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between rounded-lg border border-border dark:border-border-dark px-3 py-2">
                  <div className="flex min-w-0 items-center gap-2"><Github className="h-4 w-4 text-accent-500" /><span className="truncate text-sm font-semibold text-ink dark:text-ink-dark">Connected as @{githubUsername}</span></div>
                  <button onClick={disconnectGitHub} disabled={loading} className="inline-flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-xs font-semibold text-muted hover:bg-panel dark:hover:bg-panel-dark" title="Disconnect GitHub"><Unplug className="h-3.5 w-3.5" /> Disconnect</button>
                </div>
                <input value={repoSearch} onChange={(e) => setRepoSearch(e.target.value)} placeholder="Search repositories…" className="w-full rounded-lg border border-border dark:border-border-dark bg-surface dark:bg-surface-dark px-3 py-2 text-sm" />
                <div className="max-h-64 space-y-1 overflow-y-auto">
                  {loading && repos.length === 0 && <p className="text-sm text-muted dark:text-muted-dark">Loading repositories…</p>}
                  {filteredRepos.map((r) => (
                    <button key={r.fullName} onClick={() => setSelectedRepo(r)} className={`block w-full rounded-lg border px-3 py-2 text-left text-sm ${selectedRepo?.fullName === r.fullName ? 'border-accent-500 bg-accent-50 dark:bg-accent-500/10' : 'border-border dark:border-border-dark hover:bg-panel dark:hover:bg-panel-dark'}`}>
                      <span className="font-medium text-ink dark:text-ink-dark">{r.fullName}</span>{r.language && <span className="ml-2 text-xs text-muted dark:text-muted-dark">{r.language}</span>}
                    </button>
                  ))}
                  {!loading && filteredRepos.length === 0 && <p className="py-4 text-center text-sm text-muted dark:text-muted-dark">No matching public repositories.</p>}
                </div>
                {hasNextPage && !repoSearch && <button onClick={() => loadRepos(repoPage + 1, true)} disabled={loading} className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-border dark:border-border-dark py-2 text-xs font-semibold text-muted hover:bg-panel dark:hover:bg-panel-dark"><RefreshCw className="h-3.5 w-3.5" /> Load more</button>}
                <button onClick={handleGithubSubmit} disabled={loading || !selectedRepo} className="w-full rounded-lg bg-accent-500 py-2.5 text-sm font-semibold text-white hover:bg-accent-600 disabled:opacity-60">{loading ? 'Working…' : 'Add repository & scan'}</button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function TabButton({ active, onClick, icon: Icon, label }) {
  return <button onClick={onClick} className={`flex flex-1 items-center justify-center gap-1.5 rounded-md py-1.5 text-sm font-medium ${active ? 'bg-surface dark:bg-surface-dark text-ink dark:text-ink-dark shadow-sm' : 'text-muted dark:text-muted-dark'}`}><Icon className="h-3.5 w-3.5" /> {label}</button>;
}
