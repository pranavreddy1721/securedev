import axios from 'axios';

const productionApi = 'https://securedev.onrender.com/api';
const localApi = 'http://localhost:5000/api';
const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  (typeof window !== 'undefined' && window.location.hostname.endsWith('.pages.dev') ? productionApi : localApi);

const client = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('sd_access_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

let isRefreshing = false;
let refreshQueue = [];

client.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config || {};
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          refreshQueue.push({ resolve, reject, original });
        });
      }

      isRefreshing = true;
      const refreshToken = localStorage.getItem('sd_refresh_token');

      try {
        if (!refreshToken) throw new Error('No refresh token available');
        const { data } = await axios.post(`${API_BASE}/auth/refresh`, { refreshToken }, { timeout: 15000 });
        localStorage.setItem('sd_access_token', data.accessToken);
        localStorage.setItem('sd_refresh_token', data.refreshToken);

        refreshQueue.forEach(({ resolve, original: queued }) => {
          queued.headers = queued.headers || {};
          queued.headers.Authorization = `Bearer ${data.accessToken}`;
          resolve(client(queued));
        });
        refreshQueue = [];

        original.headers = original.headers || {};
        original.headers.Authorization = `Bearer ${data.accessToken}`;
        return client(original);
      } catch (refreshErr) {
        refreshQueue.forEach(({ reject }) => reject(refreshErr));
        refreshQueue = [];
        localStorage.removeItem('sd_access_token');
        localStorage.removeItem('sd_refresh_token');
        if (window.location.pathname !== '/login') window.location.href = '/login';
        return Promise.reject(refreshErr);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  }
);

export { API_BASE };
export default client;
