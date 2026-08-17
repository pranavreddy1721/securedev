import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { Field } from './Login';

export default function Signup() {
  const { signup } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await signup(form.name, form.email, form.password);
      navigate('/dashboard');
    } catch (err) {
      const apiErrors = err.response?.data?.errors;
      const message = apiErrors?.[0]?.msg || err.response?.data?.error || 'Signup failed. Please try again.';
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto flex min-h-[80vh] max-w-md flex-col justify-center px-6">
      <div className="text-center">
        <ShieldCheck className="mx-auto h-8 w-8 text-accent-500" />
        <h1 className="mt-3 text-2xl font-bold text-ink dark:text-ink-dark">Create your account</h1>
        <p className="mt-1 text-sm text-muted dark:text-muted-dark">Start scanning your MERN projects for free</p>
      </div>

      <form onSubmit={handleSubmit} className="mt-8 space-y-4">
        {error && (
          <div className="rounded-lg border border-severity-high/30 bg-severity-high/5 px-3 py-2 text-sm text-severity-high">
            {error}
          </div>
        )}

        <Field label="Name" value={form.name} onChange={(v) => setForm({ ...form, name: v })} required />
        <Field label="Email" type="email" value={form.email} onChange={(v) => setForm({ ...form, email: v })} required />
        <Field
          label="Password"
          type="password"
          value={form.password}
          onChange={(v) => setForm({ ...form, password: v })}
          required
          hint="At least 8 characters, with an uppercase letter and a number"
        />

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-lg bg-accent-500 py-2.5 text-sm font-semibold text-white hover:bg-accent-600 disabled:opacity-60"
        >
          {loading ? 'Creating account…' : 'Create account'}
        </button>
      </form>

      <p className="mt-6 text-center text-sm text-muted dark:text-muted-dark">
        Already have an account?{' '}
        <Link to="/login" className="font-medium text-accent-500 hover:underline">
          Sign in
        </Link>
      </p>
    </div>
  );
}
