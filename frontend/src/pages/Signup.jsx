import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Code2,
  Eye,
  EyeOff,
  Github,
  LockKeyhole,
  Mail,
  Moon,
  ShieldCheck,
  Sun,
  UserRound,
  UsersRound,
  Zap,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

const features = [
  {
    icon: ShieldCheck,
    title: 'Vulnerability Scanning',
    description: 'Detect security issues in your code',
  },
  {
    icon: Zap,
    title: 'Actionable Insights',
    description: 'Get clear, developer-friendly recommendations',
  },
  {
    icon: Code2,
    title: 'MERN Optimized',
    description: 'Built for modern web applications',
  },
  {
    icon: UsersRound,
    title: 'Free for Students',
    description: 'Learn and build securely, at no cost',
  },
];

function GoogleIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="h-5 w-5">
      <path fill="#4285F4" d="M21.35 12.27c0-.72-.06-1.42-.18-2.09H12v3.96h5.24a4.48 4.48 0 0 1-1.94 2.94v2.45h3.14c1.84-1.69 2.91-4.18 2.91-7.26Z" />
      <path fill="#34A853" d="M12 21.67c2.63 0 4.84-.87 6.45-2.36l-3.14-2.45c-.87.58-1.98.92-3.31.92-2.54 0-4.69-1.72-5.46-4.03H3.3v2.53A9.74 9.74 0 0 0 12 21.67Z" />
      <path fill="#FBBC05" d="M6.54 13.75A5.86 5.86 0 0 1 6.23 12c0-.61.11-1.2.31-1.75V7.72H3.3A9.72 9.72 0 0 0 2.27 12c0 1.56.37 3.04 1.03 4.28l3.24-2.53Z" />
      <path fill="#EA4335" d="M12 6.22c1.43 0 2.71.49 3.72 1.45l2.79-2.79C16.84 3.3 14.63 2.33 12 2.33a9.74 9.74 0 0 0-8.7 5.39l3.24 2.53c.77-2.31 2.92-4.03 5.46-4.03Z" />
    </svg>
  );
}

export default function Signup() {
  const { signup } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  function updateField(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
    if (error) setError('');
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');

    const name = form.name.trim();
    const email = form.email.trim();

    if (!name) {
      setError('Please enter your name.');
      return;
    }

    if (!email) {
      setError('Please enter your email address.');
      return;
    }

    if (form.password.length < 8 || !/[A-Z]/.test(form.password) || !/[0-9]/.test(form.password)) {
      setError('Password must be at least 8 characters and include an uppercase letter and a number.');
      return;
    }

    setLoading(true);
    try {
      await signup(name, email, form.password);
      navigate('/dashboard');
    } catch (err) {
      const apiErrors = err.response?.data?.errors;
      const message =
        apiErrors?.[0]?.msg ||
        err.response?.data?.error ||
        (err.request && !err.response
          ? 'SecureDev could not reach the API. Please check the connection and try again.'
          : 'Signup failed. Please try again.');
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  function socialNotConfigured() {
    setError('Social sign-in is not enabled yet. Create your account with email and password.');
  }

  return (
    <main className="min-h-screen overflow-hidden bg-white text-ink dark:bg-[#07111b] dark:text-ink-dark">
      <div className="relative min-h-screen lg:grid lg:grid-cols-[minmax(0,1fr)_minmax(620px,0.95fr)]">
        {/* Premium background treatment */}
        <div className="pointer-events-none absolute inset-0 overflow-hidden">
          <div className="absolute -left-32 -top-32 h-[620px] w-[620px] rounded-full bg-accent-100/70 blur-3xl dark:bg-accent-700/10" />
          <div className="absolute bottom-[-260px] left-[25%] h-[560px] w-[560px] rounded-full bg-cyan-100/60 blur-3xl dark:bg-cyan-900/10" />
          <div className="absolute right-[-180px] top-[12%] h-[620px] w-[620px] rounded-full bg-slate-100 blur-3xl dark:bg-slate-900/50" />
        </div>

        {/* Header */}
        <header className="absolute inset-x-0 top-0 z-20 flex items-center justify-between px-6 py-5 sm:px-10 lg:px-14">
          <Link to="/" className="group flex items-center gap-3">
            <span className="grid h-11 w-11 place-items-center rounded-2xl bg-accent-500 text-white shadow-lg shadow-accent-500/20">
              <ShieldCheck className="h-7 w-7" strokeWidth={2.3} />
            </span>
            <span>
              <span className="block text-[25px] font-extrabold leading-none tracking-tight text-ink dark:text-white">
                Secure<span className="text-accent-500">Dev</span>
              </span>
              <span className="mt-1 block text-xs font-medium tracking-wide text-muted dark:text-muted-dark">
                Scan. Secure. Ship Confidently.
              </span>
            </span>
          </Link>

          <div className="flex items-center gap-3 sm:gap-5">
            <button
              type="button"
              onClick={toggleTheme}
              aria-label="Toggle theme"
              className="grid h-11 w-11 place-items-center rounded-full border border-border bg-white/80 text-ink shadow-sm backdrop-blur hover:border-accent-300 hover:text-accent-600 dark:border-border-dark dark:bg-slate-900/80 dark:text-white"
            >
              {theme === 'dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </button>
            <span className="hidden text-sm font-medium text-muted dark:text-muted-dark sm:block">Already have an account?</span>
            <Link
              to="/login"
              className="rounded-xl border border-accent-500 bg-white/80 px-5 py-2.5 text-sm font-bold text-accent-600 shadow-sm backdrop-blur transition hover:bg-accent-500 hover:text-white dark:bg-slate-900/70 dark:text-accent-300"
            >
              Sign in
            </Link>
          </div>
        </header>

        {/* Left side */}
        <section className="relative hidden min-h-screen overflow-hidden px-10 pb-12 pt-36 lg:flex lg:flex-col lg:justify-center lg:px-14 xl:px-20">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_30%,rgba(20,184,156,0.18),transparent_38%),linear-gradient(135deg,#f5fffc_0%,#eef9f7_52%,#ffffff_100%)] dark:bg-[radial-gradient(circle_at_20%_30%,rgba(20,184,156,0.13),transparent_38%),linear-gradient(135deg,#071b21_0%,#07111b_70%,#07111b_100%)]" />

          {/* Decorative code/workspace panel to reproduce the reference's premium developer visual */}
          <div className="absolute bottom-[-50px] right-[-90px] h-[470px] w-[610px] rotate-[-8deg] rounded-[34px] border border-white/50 bg-slate-950/95 p-5 shadow-2xl shadow-slate-900/30 dark:border-slate-700/60">
            <div className="h-full rounded-[24px] border border-slate-700/70 bg-[#07131f] p-5 opacity-90">
              <div className="mb-5 flex items-center gap-2 border-b border-slate-700/70 pb-4">
                <span className="h-2.5 w-2.5 rounded-full bg-red-400" />
                <span className="h-2.5 w-2.5 rounded-full bg-yellow-400" />
                <span className="h-2.5 w-2.5 rounded-full bg-green-400" />
                <span className="ml-3 h-2.5 w-36 rounded bg-slate-700" />
              </div>
              <div className="space-y-3 font-mono text-xs leading-6 text-slate-500">
                <p><span className="text-purple-400">const</span> <span className="text-cyan-300">scan</span> = <span className="text-yellow-300">secureDev</span>.<span className="text-blue-300">analyze</span>(project);</p>
                <p className="pl-5"><span className="text-slate-400">→</span> dependencies checked <span className="text-emerald-400">✓</span></p>
                <p className="pl-5"><span className="text-slate-400">→</span> secrets checked <span className="text-emerald-400">✓</span></p>
                <p className="pl-5"><span className="text-slate-400">→</span> injection risks checked <span className="text-emerald-400">✓</span></p>
                <p className="pt-2"><span className="text-purple-400">return</span> <span className="text-emerald-300">secure</span>;</p>
              </div>
            </div>
          </div>

          <div className="relative z-10 max-w-[640px]">
            <span className="inline-flex items-center gap-2 rounded-full border border-accent-300/70 bg-accent-50 px-4 py-2 text-xs font-bold tracking-wide text-accent-700 shadow-sm dark:border-accent-500/30 dark:bg-accent-500/10 dark:text-accent-300">
              <Zap className="h-4 w-4" /> FREE FOR STUDENTS &amp; DEVELOPERS
            </span>

            <h1 className="mt-7 max-w-[610px] text-5xl font-black leading-[0.98] tracking-[-0.035em] text-ink dark:text-white xl:text-[64px]">
              Build Safer
              <br />
              Projects,
              <br />
              <span className="text-accent-500">Ship Confidently.</span>
            </h1>

            <p className="mt-7 max-w-[540px] text-lg leading-8 text-muted dark:text-slate-300 xl:text-xl">
              Automated vulnerability scanning, intelligent insights, and actionable fixes for your MERN projects.
            </p>

            <div className="mt-9 space-y-5">
              {features.map(({ icon: Icon, title, description }) => (
                <div key={title} className="flex items-center gap-4">
                  <span className="grid h-14 w-14 shrink-0 place-items-center rounded-2xl border border-accent-200 bg-white/75 text-accent-600 shadow-sm backdrop-blur dark:border-accent-500/30 dark:bg-slate-900/70 dark:text-accent-300">
                    <Icon className="h-6 w-6" strokeWidth={2.1} />
                  </span>
                  <div>
                    <h2 className="text-base font-extrabold text-ink dark:text-white">{title}</h2>
                    <p className="mt-0.5 text-sm text-muted dark:text-slate-400">{description}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-9 max-w-[590px] rounded-2xl border border-accent-200/80 bg-white/55 px-7 py-5 shadow-sm backdrop-blur dark:border-accent-500/20 dark:bg-slate-900/40">
              <p className="text-[16px] font-medium italic leading-7 text-slate-600 dark:text-slate-300">
                <span className="mr-2 text-4xl font-serif leading-none text-accent-500">“</span>
                Secure code today, a safer tomorrow.
              </p>
              <p className="mt-2 text-right text-sm font-semibold text-accent-700 dark:text-accent-300">— SecureDev</p>
            </div>
          </div>
        </section>

        {/* Right side / signup card */}
        <section className="relative flex min-h-screen items-center justify-center px-5 pb-12 pt-28 sm:px-8 lg:px-10 lg:pt-28">
          <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.82),rgba(241,250,248,0.94))] dark:bg-[linear-gradient(135deg,rgba(7,17,27,0.82),rgba(8,24,31,0.96))]" />

          <div className="relative z-10 w-full max-w-[650px] rounded-[26px] border border-slate-200/80 bg-white/95 p-7 shadow-[0_25px_80px_rgba(15,23,42,0.12)] backdrop-blur-xl sm:p-9 lg:p-10 dark:border-slate-700/80 dark:bg-slate-900/95 dark:shadow-black/30">
            <div className="text-center">
              <div className="mx-auto grid h-20 w-20 place-items-center rounded-full bg-accent-50 text-accent-500 shadow-inner dark:bg-accent-500/10">
                <ShieldCheck className="h-11 w-11" strokeWidth={2.2} />
              </div>
              <h1 className="mt-5 text-3xl font-black tracking-tight text-ink dark:text-white sm:text-4xl">Create your account</h1>
              <p className="mt-2 text-base text-muted dark:text-slate-400">Join SecureDev and start scanning your MERN projects for free.</p>
            </div>

            {error && (
              <div className="mt-7 flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3.5 text-sm font-medium text-red-600 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300" role="alert">
                <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="mt-7 space-y-5">
              <SignupField
                label="Name"
                icon={UserRound}
                value={form.name}
                onChange={(value) => updateField('name', value)}
                autoComplete="name"
                required
              />

              <SignupField
                label="Email"
                type="email"
                icon={Mail}
                value={form.email}
                onChange={(value) => updateField('email', value)}
                autoComplete="email"
                required
              />

              <div>
                <div className="mb-2 flex items-center justify-between">
                  <label htmlFor="signup-password" className="text-sm font-bold text-ink dark:text-white">Password</label>
                  <button
                    type="button"
                    onClick={() => setShowPassword((visible) => !visible)}
                    className="flex items-center gap-2 text-xs font-semibold text-muted transition hover:text-accent-600 dark:text-slate-400 dark:hover:text-accent-300"
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    {showPassword ? 'Hide password' : 'Show password'}
                  </button>
                </div>
                <div className="relative">
                  <LockKeyhole className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
                  <input
                    id="signup-password"
                    type={showPassword ? 'text' : 'password'}
                    value={form.password}
                    onChange={(e) => updateField('password', e.target.value)}
                    autoComplete="new-password"
                    required
                    className="h-14 w-full rounded-xl border border-slate-300 bg-white pl-12 pr-12 text-sm font-medium text-ink outline-none transition placeholder:text-slate-400 focus:border-accent-500 focus:ring-4 focus:ring-accent-500/10 dark:border-slate-600 dark:bg-slate-950/50 dark:text-white"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((visible) => !visible)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 transition hover:text-accent-600 dark:hover:text-accent-300"
                  >
                    {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                  </button>
                </div>
                <p className="mt-2 flex items-center gap-1.5 text-xs text-muted dark:text-slate-400">
                  <CheckCircle2 className="h-3.5 w-3.5 text-accent-500" />
                  At least 8 characters, with an uppercase letter and a number.
                </p>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="group flex h-14 w-full items-center justify-center gap-3 rounded-xl bg-accent-500 text-base font-extrabold text-white shadow-lg shadow-accent-500/20 transition hover:bg-accent-600 hover:shadow-xl hover:shadow-accent-500/25 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loading ? 'Creating account…' : 'Create account'}
                {!loading && <ArrowRight className="h-5 w-5 transition group-hover:translate-x-1" />}
              </button>
            </form>

            <div className="my-7 flex items-center gap-4 text-xs font-medium text-muted dark:text-slate-500">
              <span className="h-px flex-1 bg-slate-200 dark:bg-slate-700" />
              <span>or continue with</span>
              <span className="h-px flex-1 bg-slate-200 dark:bg-slate-700" />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <button
                type="button"
                onClick={socialNotConfigured}
                className="flex h-14 items-center justify-center gap-3 rounded-xl border border-slate-300 bg-white text-sm font-bold text-ink transition hover:border-slate-400 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-950/40 dark:text-white dark:hover:bg-slate-900"
              >
                <Github className="h-5 w-5" />
                Continue with GitHub
              </button>
              <button
                type="button"
                onClick={socialNotConfigured}
                className="flex h-14 items-center justify-center gap-3 rounded-xl border border-slate-300 bg-white text-sm font-bold text-ink transition hover:border-slate-400 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-950/40 dark:text-white dark:hover:bg-slate-900"
              >
                <GoogleIcon />
                Continue with Google
              </button>
            </div>

            <p className="mt-7 text-center text-sm text-muted dark:text-slate-400">
              Already have an account?{' '}
              <Link to="/login" className="font-extrabold text-accent-500 hover:text-accent-600 hover:underline">
                Sign in
              </Link>
            </p>
          </div>
        </section>

        <footer className="absolute bottom-0 left-0 right-0 z-20 flex items-center justify-between px-6 py-4 text-xs font-medium text-muted dark:text-slate-500 sm:px-10 lg:px-14 xl:px-20">
          <span>© 2026 SecureDev. Built for a safer open-source world.</span>
          <span className="hidden gap-6 sm:flex"><span>Privacy</span><span>Terms</span><span>Support</span></span>
        </footer>
      </div>
    </main>
  );
}

function SignupField({ label, icon: Icon, type = 'text', value, onChange, required, autoComplete }) {
  return (
    <div>
      <label htmlFor={`signup-${label.toLowerCase()}`} className="mb-2 block text-sm font-bold text-ink dark:text-white">
        {label}
      </label>
      <div className="relative">
        <Icon className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" />
        <input
          id={`signup-${label.toLowerCase()}`}
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required={required}
          autoComplete={autoComplete}
          className="h-14 w-full rounded-xl border border-slate-300 bg-white pl-12 pr-4 text-sm font-medium text-ink outline-none transition placeholder:text-slate-400 focus:border-accent-500 focus:ring-4 focus:ring-accent-500/10 dark:border-slate-600 dark:bg-slate-950/50 dark:text-white"
        />
      </div>
    </div>
  );
}
