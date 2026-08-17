import { Link, useNavigate } from 'react-router-dom';
import { Moon, Sun, ShieldCheck, LogOut } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

export default function Navbar() {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate('/login');
  }

  return (
    <nav className="sticky top-0 z-10 border-b border-border dark:border-border-dark bg-surface/80 dark:bg-surface-dark/80 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link to={user ? '/dashboard' : '/'} className="flex items-center gap-2 font-bold text-ink dark:text-ink-dark">
          <ShieldCheck className="h-5 w-5 text-accent-500" />
          SecureDev
        </Link>

        <div className="flex items-center gap-4">
          <button
            onClick={toggleTheme}
            aria-label="Toggle dark mode"
            className="rounded-lg p-2 text-muted hover:bg-panel dark:text-muted-dark dark:hover:bg-panel-dark"
          >
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>

          {user ? (
            <div className="flex items-center gap-3">
              <span className="hidden text-sm text-muted dark:text-muted-dark sm:inline">{user.name}</span>
              <button
                onClick={handleLogout}
                className="flex items-center gap-1 rounded-lg border border-border dark:border-border-dark px-3 py-1.5 text-sm text-ink dark:text-ink-dark hover:bg-panel dark:hover:bg-panel-dark"
              >
                <LogOut className="h-3.5 w-3.5" /> Logout
              </button>
            </div>
          ) : (
            <Link
              to="/login"
              className="rounded-lg bg-accent-500 px-4 py-1.5 text-sm font-medium text-white hover:bg-accent-600"
            >
              Sign in
            </Link>
          )}
        </div>
      </div>
    </nav>
  );
}
