const BAND_COLORS = {
  'Low Risk': '#16a34a',
  'Medium Risk': '#d97706',
  'High Risk': '#ea580c',
  'Critical Risk': '#dc2626',
};

function bandForScore(score) {
  if (score >= 80) return 'Low Risk';
  if (score >= 60) return 'Medium Risk';
  if (score >= 40) return 'High Risk';
  return 'Critical Risk';
}

/**
 * SVG radial progress gauge for the security score — the dashboard's
 * visual centerpiece per the confirmed design direction.
 */
export default function RadialGauge({ score = 0, size = 220, strokeWidth = 16, label }) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const offset = circumference - (clamped / 100) * circumference;
  const band = bandForScore(clamped);
  const color = BAND_COLORS[band];

  return (
    <div className="flex flex-col items-center" style={{ width: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth={strokeWidth}
          className="stroke-panel dark:stroke-panel-dark"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 800ms ease-out' }}
        />
      </svg>
      <div className="flex flex-col items-center" style={{ marginTop: -(size / 1.65) }}>
        <span className="text-5xl font-extrabold tabular-nums" style={{ color }}>
          {Math.round(clamped)}
        </span>
        <span className="text-sm text-muted dark:text-muted-dark">/ 100</span>
      </div>
      <div className="mt-3 text-center">
        <span
          className="inline-block rounded-full px-3 py-1 text-xs font-semibold text-white"
          style={{ backgroundColor: color }}
        >
          {band}
        </span>
        {label && <p className="mt-2 text-xs text-muted dark:text-muted-dark">{label}</p>}
      </div>
    </div>
  );
}
