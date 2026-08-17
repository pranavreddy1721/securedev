import { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import client from '../api/client';
import { LoadingState, EmptyState, ErrorState } from '../components/AsyncStates';
import { History } from 'lucide-react';

const BAND_COLORS = {
  'Low Risk': '#16a34a',
  'Medium Risk': '#d97706',
  'High Risk': '#ea580c',
  'Critical Risk': '#dc2626',
};

export default function ScanHistory() {
  const { projectId } = useParams();
  const [scans, setScans] = useState(null);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    client
      .get(`/scans/project/${projectId}/history`)
      .then(({ data }) => setScans(data.scans))
      .catch(() => setError('Failed to load scan history.'));
  }, [projectId]);

  if (error) return <div className="mx-auto max-w-4xl px-6 py-10"><ErrorState message={error} /></div>;
  if (!scans) return <LoadingState label="Loading scan history…" />;

  const completed = scans.filter((s) => s.status === 'completed').slice().reverse();
  const chartData = completed.map((s) => ({
    date: new Date(s.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    score: s.finalScore,
  }));

  return (
    <div className="mx-auto max-w-4xl px-6 py-10">
      <h1 className="text-2xl font-bold text-ink dark:text-ink-dark">Scan history</h1>
      <p className="mt-1 text-sm text-muted dark:text-muted-dark">All past scans for this project.</p>

      {scans.length === 0 ? (
        <div className="mt-8">
          <EmptyState icon={History} title="No scans yet" description="Run a scan from the dashboard to see history here." />
        </div>
      ) : (
        <>
          {chartData.length > 1 && (
            <div className="mt-8 h-56 rounded-xl border border-border dark:border-border-dark bg-panel dark:bg-panel-dark p-4">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border dark:stroke-border-dark" />
                  <XAxis dataKey="date" tick={{ fontSize: 12 }} stroke="currentColor" className="text-muted dark:text-muted-dark" />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} stroke="currentColor" className="text-muted dark:text-muted-dark" />
                  <Tooltip contentStyle={{ background: '#111a2e', border: 'none', borderRadius: 8, fontSize: 12 }} />
                  <Line type="monotone" dataKey="score" stroke="#14b89c" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          <div className="mt-6 overflow-hidden rounded-xl border border-border dark:border-border-dark">
            <table className="w-full text-sm">
              <thead className="bg-panel dark:bg-panel-dark text-left text-xs uppercase text-muted dark:text-muted-dark">
                <tr>
                  <th className="px-4 py-3">Date</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Risk band</th>
                  <th className="px-4 py-3">Duration</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border dark:divide-border-dark">
                {scans.map((s) => (
                  <tr
                    key={s._id}
                    onClick={() => s.status === 'completed' && navigate(`/scans/${s._id}`)}
                    className={s.status === 'completed' ? 'cursor-pointer hover:bg-panel dark:hover:bg-panel-dark' : ''}
                  >
                    <td className="px-4 py-3 text-ink dark:text-ink-dark">{new Date(s.createdAt).toLocaleString()}</td>
                    <td className="px-4 py-3 capitalize text-muted dark:text-muted-dark">{s.status}</td>
                    <td className="px-4 py-3 font-semibold text-ink dark:text-ink-dark">{s.finalScore ?? '—'}</td>
                    <td className="px-4 py-3">
                      {s.riskBand ? (
                        <span className="font-medium" style={{ color: BAND_COLORS[s.riskBand] }}>
                          {s.riskBand}
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="px-4 py-3 text-muted dark:text-muted-dark">
                      {s.durationMs ? `${Math.round(s.durationMs / 1000)}s` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <Link to="/dashboard" className="mt-6 inline-block text-sm font-medium text-accent-500 hover:underline">
        ← Back to dashboard
      </Link>
    </div>
  );
}
