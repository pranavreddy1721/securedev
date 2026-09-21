import { Link } from 'react-router-dom';
import { ArrowRight, CheckCircle2, FileText, ShieldCheck, Sparkles, Zap } from 'lucide-react';

const features = [
  { icon: ShieldCheck, title: 'Security scanning', desc: 'Dependency, secret, pattern and heuristic checks in one workflow.' },
  { icon: Zap, title: 'Parallel analysis', desc: 'Multiple engines run together so you get a result without tool hopping.' },
  { icon: FileText, title: 'Decision-ready reports', desc: 'A unified score, categorized findings and downloadable PDF reporting.' },
];

const steps = [
  { n: '01', title: 'Bring your project', desc: 'Upload a ZIP or connect a GitHub repository.' },
  { n: '02', title: 'Run the scan', desc: 'SecureDev orchestrates the security engines automatically.' },
  { n: '03', title: 'Fix what matters', desc: 'Review severity, evidence, score and AI-assisted remediation.' },
];

export default function Landing() {
  return (
    <main className="overflow-hidden bg-[#f6faf9] text-slate-950 dark:bg-[#061218] dark:text-white">
      <section className="relative min-h-[calc(100vh-76px)]">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_72%_12%,rgba(20,184,156,0.16),transparent_28%),radial-gradient(circle_at_12%_70%,rgba(56,189,248,0.10),transparent_25%)]" />
        <div className="mx-auto grid max-w-7xl gap-14 px-6 pb-20 pt-16 lg:grid-cols-[1.02fr_.98fr] lg:items-center lg:px-10 lg:pt-20">
          <div className="relative z-10">
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-white/80 px-4 py-2 text-xs font-bold tracking-[0.14em] text-emerald-700 shadow-sm dark:border-emerald-500/20 dark:bg-white/5 dark:text-emerald-300">
              <Sparkles className="h-4 w-4" /> DEVSECOPS FOR MERN
            </div>
            <h1 className="mt-7 max-w-3xl text-5xl font-black tracking-[-0.045em] sm:text-6xl lg:text-[76px] lg:leading-[0.94]">
              Ship code with
              <span className="block text-emerald-500">security built in.</span>
            </h1>
            <p className="mt-7 max-w-2xl text-lg leading-8 text-slate-600 dark:text-slate-300 sm:text-xl">
              SecureDev turns a MERN project into a clear security assessment — scanning dependencies, secrets and risky code patterns, then bringing everything together in one report.
            </p>
            <div className="mt-9 flex flex-col gap-3 sm:flex-row">
              <Link to="/signup" className="group inline-flex items-center justify-center gap-2 rounded-2xl bg-slate-950 px-6 py-3.5 text-sm font-bold text-white shadow-xl shadow-slate-900/15 transition hover:-translate-y-0.5 dark:bg-emerald-500 dark:text-slate-950">
                Start scanning free <ArrowRight className="h-4 w-4 transition group-hover:translate-x-1" />
              </Link>
              <Link to="/login" className="inline-flex items-center justify-center rounded-2xl border border-slate-200 bg-white/80 px-6 py-3.5 text-sm font-bold text-slate-800 shadow-sm hover:border-emerald-300 dark:border-slate-700 dark:bg-white/5 dark:text-white">
                Sign in
              </Link>
            </div>
            <div className="mt-9 flex flex-wrap gap-x-6 gap-y-3 text-sm text-slate-500 dark:text-slate-400">
              {['Student friendly', 'No security setup required', 'MERN focused'].map((item) => (
                <span key={item} className="inline-flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-emerald-500" />{item}</span>
              ))}
            </div>
          </div>

          <div className="relative z-10">
            <div className="absolute -inset-8 rounded-[42px] bg-emerald-400/10 blur-3xl" />
            <div className="relative overflow-hidden rounded-[32px] border border-slate-200/80 bg-white/90 p-4 shadow-[0_30px_100px_rgba(15,23,42,0.14)] backdrop-blur-xl dark:border-slate-700 dark:bg-slate-900/90">
              <div className="rounded-[24px] bg-[#07131a] p-5 text-white shadow-inner">
                <div className="flex items-center justify-between border-b border-white/10 pb-4">
                  <div className="flex items-center gap-2"><ShieldCheck className="h-5 w-5 text-emerald-400" /><span className="font-bold">Security overview</span></div>
                  <span className="rounded-full bg-emerald-400/10 px-3 py-1 text-xs font-semibold text-emerald-300">LIVE SCAN</span>
                </div>
                <div className="grid gap-4 py-5 sm:grid-cols-2">
                  <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-5">
                    <div className="text-xs uppercase tracking-widest text-slate-500">Security score</div>
                    <div className="mt-4 flex items-end gap-2"><span className="text-6xl font-black text-emerald-400">88</span><span className="mb-2 text-sm text-slate-400">/ 100</span></div>
                    <div className="mt-4 h-2 rounded-full bg-white/10"><div className="h-full w-[88%] rounded-full bg-emerald-400" /></div>
                    <div className="mt-3 text-xs text-emerald-300">Low risk assessment</div>
                  </div>
                  <div className="space-y-3">
                    {['Dependency Security', 'Authentication', 'Secrets Detection', 'OWASP Compliance'].map((label, i) => (
                      <div key={label} className="rounded-xl border border-white/10 bg-white/[0.035] p-3">
                        <div className="flex justify-between text-xs"><span className="text-slate-400">{label}</span><span>{[100, 100, 100, 39][i]}</span></div>
                        <div className="mt-2 h-1.5 rounded-full bg-white/10"><div className="h-full rounded-full bg-emerald-400" style={{ width: `${[100, 100, 100, 39][i]}%` }} /></div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="rounded-2xl border border-white/10 bg-black/20 p-4 font-mono text-xs leading-6 text-slate-400">
                  <div><span className="text-emerald-400">$</span> securedev scan ./my-project</div>
                  <div className="text-emerald-300">✓ npm audit completed</div>
                  <div className="text-emerald-300">✓ secret scanner completed</div>
                  <div className="text-emerald-300">✓ semgrep completed</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="border-y border-slate-200 bg-white py-20 dark:border-slate-800 dark:bg-[#08171e]">
        <div className="mx-auto max-w-7xl px-6 lg:px-10">
          <div className="max-w-2xl">
            <p className="text-xs font-bold uppercase tracking-[0.18em] text-emerald-600">One workflow, several security layers</p>
            <h2 className="mt-3 text-3xl font-black tracking-tight sm:text-4xl">Everything your MERN project needs to see risk clearly.</h2>
          </div>
          <div className="mt-10 grid gap-5 lg:grid-cols-3">
            {features.map(({ icon: Icon, title, desc }) => (
              <article key={title} className="group rounded-3xl border border-slate-200 bg-slate-50 p-7 transition hover:-translate-y-1 hover:border-emerald-300 hover:bg-white hover:shadow-xl dark:border-slate-800 dark:bg-slate-900/50 dark:hover:bg-slate-900">
                <span className="grid h-12 w-12 place-items-center rounded-2xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"><Icon className="h-6 w-6" /></span>
                <h3 className="mt-6 text-lg font-extrabold">{title}</h3>
                <p className="mt-2 text-sm leading-7 text-slate-600 dark:text-slate-400">{desc}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20">
        <div className="mx-auto max-w-7xl px-6 lg:px-10">
          <div className="grid gap-12 lg:grid-cols-[.75fr_1.25fr] lg:items-center">
            <div>
              <p className="text-xs font-bold uppercase tracking-[0.18em] text-emerald-600">Simple by design</p>
              <h2 className="mt-3 text-4xl font-black tracking-tight">From source code to security report in three moves.</h2>
              <p className="mt-5 leading-7 text-slate-600 dark:text-slate-400">No scattered dashboards. No manual spreadsheet of findings. Just a focused workflow designed around how developers actually work.</p>
            </div>
            <div className="grid gap-4">
              {steps.map((step) => (
                <div key={step.n} className="flex gap-5 rounded-3xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900/50">
                  <div className="font-mono text-sm font-bold text-emerald-500">{step.n}</div>
                  <div><h3 className="font-extrabold">{step.title}</h3><p className="mt-1 text-sm leading-6 text-slate-500 dark:text-slate-400">{step.desc}</p></div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="px-6 pb-20 lg:px-10">
        <div className="mx-auto max-w-7xl overflow-hidden rounded-[32px] bg-slate-950 px-7 py-12 text-white sm:px-12 dark:bg-emerald-500 dark:text-slate-950">
          <div className="flex flex-col justify-between gap-8 lg:flex-row lg:items-center">
            <div><p className="text-sm font-bold uppercase tracking-widest text-emerald-300 dark:text-slate-800">Ready when you are</p><h2 className="mt-2 text-3xl font-black">Secure your next MERN project before you ship it.</h2></div>
            <Link to="/signup" className="inline-flex shrink-0 items-center justify-center gap-2 rounded-2xl bg-white px-6 py-3 font-bold text-slate-950 hover:bg-slate-100 dark:bg-slate-950 dark:text-white">Create free account <ArrowRight className="h-4 w-4" /></Link>
          </div>
        </div>
      </section>
    </main>
  );
}
