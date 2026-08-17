import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(form.email, form.password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto flex min-h-[80vh] max-w-md flex-col justify-center px-6">
      <div className="text-center">
        <ShieldCheck className="mx-auto h-8 w-8 text-accent-500" />
        <h1 className="mt-3 text-2xl font-bold text-ink dark:text-ink-dark">Welcome back</h1>
        <p className="mt-1 text-sm text-muted dark:text-muted-dark">Sign in to your SecureDev account</p>
      </div>

      <form onSubmit={handleSubmit} className="mt-8 space-y-4">
        {error && (
          <div className="rounded-lg border border-severity-high/30 bg-severity-high/5 px-3 py-2 text-sm text-severity-high">
            {error}
          </div>
        )}

        <Field label="Email" type="email" value={form.email} onChange={(v) => setForm({ ...form, email: v })} required />
        <Field
          label="Password"
          type="password"
          value={form.password}
          onChange={(v) => setForm({ ...form, password: v })}
          required
        />

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-lg bg-accent-500 py-2.5 text-sm font-semibold text-white hover:bg-accent-600 disabled:opacity-60"
        >
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      <p className="mt-6 text-center text-sm text-muted dark:text-muted-dark">
        Don't have an account?{' '}
        <Link to="/signup" className="font-medium text-accent-500 hover:underline">
          Sign up
        </Link>
      </p>
    </div>
  );
}

export function Field({ label, type = 'text', value, onChange, required, hint }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-ink dark:text-ink-dark">{label}</span>
      <input
        type={type}
        value={value}
        required={required}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg border border-border dark:border-border-dark bg-surface dark:bg-surface-dark px-3 py-2 text-sm text-ink dark:text-ink-dark placeholder:text-muted focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500"
      />
      {hint && <span className="mt-1 block text-xs text-muted dark:text-muted-dark">{hint}</span>}
    </label>
  );
}
