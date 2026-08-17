import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import client from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadMe = useCallback(async () => {
    const token = localStorage.getItem('sd_access_token');
    if (!token) {
      setLoading(false);
      return;
    }
    try {
      const { data } = await client.get('/auth/me');
      setUser(data.user);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadMe();
  }, [loadMe]);

  async function login(email, password) {
    const { data } = await client.post('/auth/login', { email, password });
    localStorage.setItem('sd_access_token', data.accessToken);
    localStorage.setItem('sd_refresh_token', data.refreshToken);
    setUser(data.user);
    return data.user;
  }

  async function signup(name, email, password) {
    const { data } = await client.post('/auth/signup', { name, email, password });
    localStorage.setItem('sd_access_token', data.accessToken);
    localStorage.setItem('sd_refresh_token', data.refreshToken);
    setUser(data.user);
    return data.user;
  }

  async function logout() {
    try {
      await client.post('/auth/logout');
    } catch {
      // ignore — clearing local tokens is what actually matters client-side
    }
    localStorage.removeItem('sd_access_token');
    localStorage.removeItem('sd_refresh_token');
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, logout, refreshUser: loadMe }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
