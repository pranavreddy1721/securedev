import axios from 'axios';

const productionApi = 'https://securedev.onrender.com/api';
const localApi = 'http://localhost:5000/api';
const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  (typeof window !== 'undefined' && window.location.hostname.endsWith('.pages.dev') ? productionApi : localApi);

const client = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
});

let isRefreshing = false;
let refreshQueue = [];

client.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config || {};
    if (error.response?.status === 401 && !original._retry && !original.url?.endsWith('/auth/refresh')) {
      original._retry = true;

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          refreshQueue.push({ resolve, reject, original });
        });
      }

      isRefreshing = true;

      try {
        await axios.post(
          `${API_BASE}/auth/refresh`,
          {},
          { timeout: 15000, withCredentials: true }
        );

        refreshQueue.forEach(({ resolve, original: queued }) => resolve(client(queued)));
        refreshQueue = [];
        return client(original);
      } catch (refreshErr) {
        refreshQueue.forEach(({ reject }) => reject(refreshErr));
        refreshQueue = [];
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
