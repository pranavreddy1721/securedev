import { Link, useLocation, useNavigate } from 'react-router-dom';
import { LayoutDashboard, LogOut, Moon, ShieldCheck, Sun } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

export default function Navbar() {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();

  async function handleLogout() {
    await logout();
    navigate('/login');
  }

  const active = location.pathname === '/dashboard' || location.pathname.startsWith('/projects/') || location.pathname.startsWith('/scans/');

  return (
    <header className="sticky top-0 z-40 border-b border-slate-200/80 bg-white/85 backdrop-blur-xl dark:border-slate-800 dark:bg-[#07131a]/90">
      <div className="mx-auto flex h-[76px] max-w-7xl items-center justify-between px-5 lg:px-8">
        <Link to={user ? '/dashboard' : '/'} className="flex items-center gap-3">
          <span className="grid h-10 w-10 place-items-center rounded-xl bg-emerald-500 text-white shadow-lg shadow-emerald-500/20"><ShieldCheck className="h-6 w-6" /></span>
          <span className="text-xl font-black tracking-tight text-slate-950 dark:text-white">Secure<span className="text-emerald-500">Dev</span></span>
        </Link>

        <nav className="hidden items-center gap-1 md:flex">
          {user ? <Link to="/dashboard" className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-bold ${active ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' : 'text-slate-500 dark:text-slate-400'}`}><LayoutDashboard className="h-4 w-4" /> Workspace</Link> : <><a href="/#features" className="px-4 py-2 text-sm font-semibold text-slate-500 hover:text-slate-950 dark:text-slate-400 dark:hover:text-white">Features</a><a href="/#how-it-works" className="px-4 py-2 text-sm font-semibold text-slate-500 hover:text-slate-950 dark:text-slate-400 dark:hover:text-white">How it works</a></>}
        </nav>

        <div className="flex items-center gap-3">
          <button onClick={toggleTheme} aria-label="Toggle theme" className="grid h-10 w-10 place-items-center rounded-full border border-slate-200 bg-white text-slate-600 shadow-sm hover:border-emerald-300 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200">{theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}</button>
          {user ? <><div className="hidden items-center gap-2 rounded-full border border-slate-200 bg-white py-1.5 pl-1.5 pr-3 sm:flex dark:border-slate-700 dark:bg-slate-900"><span className="grid h-8 w-8 place-items-center rounded-full bg-emerald-500/10 text-xs font-black text-emerald-600 dark:text-emerald-400">{user.name?.slice(0, 1).toUpperCase()}</span><span className="max-w-[120px] truncate text-sm font-semibold text-slate-700 dark:text-slate-200">{user.name}</span></div><button onClick={handleLogout} className="grid h-10 w-10 place-items-center rounded-full border border-slate-200 text-slate-500 hover:border-red-200 hover:text-red-600 dark:border-slate-700" aria-label="Logout"><LogOut className="h-4 w-4" /></button></> : <Link to="/login" className="rounded-xl bg-emerald-500 px-5 py-2.5 text-sm font-bold text-white shadow-md shadow-emerald-500/15 hover:bg-emerald-600">Sign in</Link>}
        </div>
      </div>
    </header>
  );
}
