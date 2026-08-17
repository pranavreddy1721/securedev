import { Link } from 'react-router-dom';
import { ShieldCheck, Zap, FileText, GitBranch } from 'lucide-react';

export default function Landing() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-20">
      <div className="text-center">
        <span className="inline-flex items-center gap-1.5 rounded-full border border-border dark:border-border-dark bg-panel dark:bg-panel-dark px-3 py-1 text-xs font-medium text-muted dark:text-muted-dark">
          <ShieldCheck className="h-3.5 w-3.5 text-accent-500" /> Built for the MERN stack
        </span>
        <h1 className="mt-6 text-4xl font-extrabold tracking-tight text-ink dark:text-ink-dark sm:text-5xl">
          One click. Every scanner.
          <br />
          <span className="text-accent-500">One security score.</span>
        </h1>
        <p className="mx-auto mt-5 max-w-xl text-base text-muted dark:text-muted-dark">
          SecureDev orchestrates dependency, secret, and code-pattern scanning behind a single
          unified score — no separate tool setup, no expertise required.
        </p>
        <div className="mt-8 flex justify-center gap-3">
          <Link
            to="/signup"
            className="rounded-lg bg-accent-500 px-6 py-3 text-sm font-semibold text-white hover:bg-accent-600"
          >
            Get started free
          </Link>
          <Link
            to="/login"
            className="rounded-lg border border-border dark:border-border-dark px-6 py-3 text-sm font-semibold text-ink dark:text-ink-dark hover:bg-panel dark:hover:bg-panel-dark"
          >
            Sign in
          </Link>
        </div>
      </div>

      <div className="mt-20 grid gap-6 sm:grid-cols-3">
        <Feature icon={GitBranch} title="Upload or connect" desc="Bring a .zip or connect a GitHub repo via OAuth — no config files to write." />
        <Feature icon={Zap} title="Parallel orchestration" desc="npm audit, secret scanning, and Semgrep run concurrently against your project." />
        <Feature icon={FileText} title="One report" desc="A weighted 0–100 score, severity-coded findings, and a downloadable PDF." />
      </div>
    </div>
  );
}

function Feature({ icon: Icon, title, desc }) {
  return (
    <div className="rounded-xl border border-border dark:border-border-dark bg-panel dark:bg-panel-dark p-5">
      <Icon className="h-5 w-5 text-accent-500" />
      <h3 className="mt-3 font-semibold text-ink dark:text-ink-dark">{title}</h3>
      <p className="mt-1 text-sm text-muted dark:text-muted-dark">{desc}</p>
    </div>
  );
}
