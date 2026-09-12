import axios from 'axios';
import { HealthCheckStatus } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 45000,
});

// Request Interceptor: Attach Bearer Token if available
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('mailshield_access_token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value?: unknown) => void;
  reject: (reason?: unknown) => void;
}> = [];

const processQueue = (error: any, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// Response Interceptor: Catch 401 Unauthorized, auto-refresh JWT, or redirect to login
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      const isAuthUrl = originalRequest.url?.includes('/auth/login') || 
                        originalRequest.url?.includes('/auth/refresh') ||
                        originalRequest.url?.includes('/auth/google');
      
      const refreshToken = localStorage.getItem('mailshield_refresh_token');

      if (!isAuthUrl && refreshToken) {
        if (isRefreshing) {
          return new Promise((resolve, reject) => {
            failedQueue.push({ resolve, reject });
          })
            .then((token) => {
              originalRequest.headers.Authorization = `Bearer ${token}`;
              return apiClient(originalRequest);
            })
            .catch((err) => Promise.reject(err));
        }

        originalRequest._retry = true;
        isRefreshing = true;

        try {
          const res = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken,
          });

          const { access_token, refresh_token: newRefreshToken } = res.data;
          localStorage.setItem('mailshield_access_token', access_token);
          if (newRefreshToken) {
            localStorage.setItem('mailshield_refresh_token', newRefreshToken);
          }

          apiClient.defaults.headers.common.Authorization = `Bearer ${access_token}`;
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          processQueue(null, access_token);
          return apiClient(originalRequest);
        } catch (refreshErr) {
          processQueue(refreshErr, null);
          localStorage.removeItem('mailshield_access_token');
          localStorage.removeItem('mailshield_refresh_token');
          if (window.location.pathname !== '/login') {
            window.location.href = `/login`;
          }
          return Promise.reject(refreshErr);
        } finally {
          isRefreshing = false;
        }
      }

      // No refresh token available or auth endpoint failed
      localStorage.removeItem('mailshield_access_token');
      localStorage.removeItem('mailshield_refresh_token');
      if (window.location.pathname !== '/login') {
        window.location.href = `/login`;
      }
    }
    return Promise.reject(error);
  }
);

export const healthApi = {
  checkHealth: async (): Promise<HealthCheckStatus> => {
    const response = await apiClient.get<HealthCheckStatus>('/health');
    return response.data;
  },
};
