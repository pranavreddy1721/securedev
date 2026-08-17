import { AlertTriangle, Inbox, Loader2 } from 'lucide-react';

export function LoadingState({ label = 'Loading…' }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16 text-muted dark:text-muted-dark">
      <Loader2 className="h-6 w-6 animate-spin text-accent-500" />
      <p className="text-sm">{label}</p>
    </div>
  );
}

export function EmptyState({ icon: Icon = Inbox, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border dark:border-border-dark py-16 px-6 text-center">
      <Icon className="h-8 w-8 text-muted dark:text-muted-dark" />
      <h3 className="text-base font-semibold text-ink dark:text-ink-dark">{title}</h3>
      {description && <p className="max-w-sm text-sm text-muted dark:text-muted-dark">{description}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ message = 'Something went wrong.', onRetry }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-severity-high/30 bg-severity-high/5 py-12 px-6 text-center">
      <AlertTriangle className="h-7 w-7 text-severity-high" />
      <p className="text-sm text-ink dark:text-ink-dark">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="rounded-lg bg-severity-high px-4 py-2 text-sm font-medium text-white hover:opacity-90"
        >
          Try again
        </button>
      )}
    </div>
  );
}
