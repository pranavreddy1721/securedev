import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { LoadingState } from './AsyncStates';

export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <LoadingState label="Loading…" />;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}
