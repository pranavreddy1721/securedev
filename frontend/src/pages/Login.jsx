import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AlertCircle, ArrowRight, Eye, EyeOff, LockKeyhole, Mail, Moon, ShieldCheck, Sun } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

export default function Login() {
  const { login } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: '', password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    if (!form.email.trim() || !form.password) return setError('Enter your email and password to continue.');
    setLoading(true);
    try {
      await login(form.email.trim(), form.password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.error || (err.request && !err.response ? 'SecureDev could not reach the API. Check your connection and try again.' : 'Login failed. Please check your credentials.'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-[calc(100vh-76px)] overflow-hidden bg-[#f5f9f8] dark:bg-[#061218]">
      <div className="mx-auto grid min-h-[calc(100vh-76px)] max-w-7xl lg:grid-cols-[1fr_0.9fr]">
        <section className="relative hidden overflow-hidden px-10 py-16 lg:flex lg:flex-col lg:justify-center xl:px-20">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_30%,rgba(20,184,156,.18),transparent_34%),linear-gradient(145deg,#eafaf6,#f8fcfb)] dark:bg-[radial-gradient(circle_at_20%_30%,rgba(20,184,156,.13),transparent_34%),linear-gradient(145deg,#071b21,#061218)]" />
          <div className="relative z-10 max-w-xl">
            <span className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-white/70 px-4 py-2 text-xs font-bold tracking-[0.16em] text-emerald-700 dark:border-emerald-500/20 dark:bg-white/5 dark:text-emerald-300"><ShieldCheck className="h-4 w-4" /> SECURE DEVELOPMENT</span>
            <h1 className="mt-7 text-5xl font-black tracking-[-0.045em] text-slate-950 dark:text-white xl:text-6xl">Welcome back to a clearer view of your code.</h1>
            <p className="mt-6 max-w-lg text-lg leading-8 text-slate-600 dark:text-slate-300">Pick up where you left off, review previous scans, and keep your projects moving toward a stronger security posture.</p>
            <div className="mt-10 overflow-hidden rounded-[28px] border border-slate-200 bg-[#07131a] p-5 shadow-2xl dark:border-slate-700">
              <div className="flex items-center justify-between border-b border-white/10 pb-4 text-sm"><span className="font-bold text-white">Latest scan</span><span className="text-emerald-300">Completed</span></div>
              <div className="grid grid-cols-[auto_1fr] items-center gap-5 py-6">
                <div className="grid h-28 w-28 place-items-center rounded-full border-[10px] border-emerald-400/20 border-t-emerald-400 border-r-emerald-400 text-3xl font-black text-white">88</div>
                <div className="space-y-3">
                  {['Dependencies', 'Secrets', 'Code patterns'].map((label, i) => <div key={label}><div className="flex justify-between text-xs text-slate-400"><span>{label}</span><span className="text-white">{[100, 100, 91][i]}</span></div><div className="mt-1.5 h-1.5 rounded-full bg-white/10"><div className="h-full rounded-full bg-emerald-400" style={{ width: `${[100, 100, 91][i]}%` }} /></div></div>)}
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="flex items-center justify-center px-5 py-12 sm:px-8 lg:px-12">
          <div className="w-full max-w-[520px]">
            <div className="mb-6 flex justify-end"><button type="button" onClick={toggleTheme} className="grid h-11 w-11 place-items-center rounded-full border border-slate-200 bg-white text-slate-700 shadow-sm dark:border-slate-700 dark:bg-slate-900 dark:text-white" aria-label="Toggle theme">{theme === 'dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}</button></div>
            <div className="rounded-[30px] border border-slate-200 bg-white p-7 shadow-[0_30px_90px_rgba(15,23,42,.10)] sm:p-10 dark:border-slate-700 dark:bg-slate-900 dark:shadow-black/30">
              <div className="text-center">
                <div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl bg-emerald-500/10 text-emerald-500"><ShieldCheck className="h-9 w-9" /></div>
                <h1 className="mt-5 text-3xl font-black tracking-tight text-slate-950 dark:text-white">Sign in to SecureDev</h1>
                <p className="mt-2 text-sm leading-6 text-slate-500 dark:text-slate-400">Access your projects, scans and security reports.</p>
              </div>
              {error && <div className="mt-7 flex gap-3 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300"><AlertCircle className="h-5 w-5 shrink-0" /> <span>{error}</span></div>}
              <form onSubmit={handleSubmit} className="mt-7 space-y-5">
                <Field label="Email" icon={Mail} type="email" value={form.email} onChange={(v) => setForm({ ...form, email: v })} required autoComplete="email" />
                <div>
                  <div className="flex items-center justify-between"><label className="text-sm font-bold text-slate-800 dark:text-slate-200">Password</label><span className="text-xs text-slate-400">Your account password</span></div>
                  <div className="relative mt-2"><LockKeyhole className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" /><input type={showPassword ? 'text' : 'password'} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required autoComplete="current-password" className="w-full rounded-2xl border border-slate-200 bg-slate-50 py-3.5 pl-12 pr-12 text-sm text-slate-900 outline-none transition focus:border-emerald-400 focus:bg-white focus:ring-4 focus:ring-emerald-500/10 dark:border-slate-700 dark:bg-slate-800 dark:text-white dark:focus:bg-slate-900" /><button type="button" onClick={() => setShowPassword((v) => !v)} className="absolute right-3 top-1/2 grid h-9 w-9 -translate-y-1/2 place-items-center rounded-xl text-slate-400 hover:bg-slate-200/60 dark:hover:bg-slate-700" aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}</button></div>
                </div>
                <button disabled={loading} className="group flex w-full items-center justify-center gap-2 rounded-2xl bg-emerald-500 py-3.5 text-sm font-extrabold text-white shadow-lg shadow-emerald-500/20 transition hover:bg-emerald-600 disabled:cursor-not-allowed disabled:opacity-60">{loading ? 'Signing in…' : <>Sign in <ArrowRight className="h-4 w-4 transition group-hover:translate-x-1" /></>}</button>
              </form>
              <div className="mt-7 text-center text-sm text-slate-500 dark:text-slate-400">New to SecureDev? <Link to="/signup" className="font-extrabold text-emerald-600 hover:text-emerald-700 dark:text-emerald-400">Create an account</Link></div>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

function Field({ label, icon: Icon, type = 'text', value, onChange, required, autoComplete }) {
  return <label className="block"><span className="text-sm font-bold text-slate-800 dark:text-slate-200">{label}</span><div className="relative mt-2"><Icon className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-400" /><input type={type} value={value} required={required} autoComplete={autoComplete} onChange={(e) => onChange(e.target.value)} className="w-full rounded-2xl border border-slate-200 bg-slate-50 py-3.5 pl-12 pr-4 text-sm text-slate-900 outline-none transition focus:border-emerald-400 focus:bg-white focus:ring-4 focus:ring-emerald-500/10 dark:border-slate-700 dark:bg-slate-800 dark:text-white dark:focus:bg-slate-900" /></div></label>;
}
