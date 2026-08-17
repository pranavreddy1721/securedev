const STYLES = {
  critical: 'bg-severity-critical/10 text-severity-critical border-severity-critical/30',
  high: 'bg-severity-high/10 text-severity-high border-severity-high/30',
  medium: 'bg-severity-medium/10 text-severity-medium border-severity-medium/30',
  low: 'bg-severity-low/10 text-severity-low border-severity-low/30',
};

export default function SeverityBadge({ severity }) {
  const style = STYLES[severity] || STYLES.low;
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${style}`}>
      {severity}
    </span>
  );
}
