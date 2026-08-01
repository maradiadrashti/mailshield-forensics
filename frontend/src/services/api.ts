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

export const healthApi = {
  checkHealth: async (): Promise<HealthCheckStatus> => {
    const response = await apiClient.get<HealthCheckStatus>('/health');
    return response.data;
  },
};
