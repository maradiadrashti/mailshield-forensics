import { apiClient } from './api';
import { TokenResponse, User } from '../types';

export const authApi = {
  getGoogleLoginUrl: async (): Promise<{ url: string }> => {
    const response = await apiClient.get<{ url: string }>('/auth/google/login');
    return response.data;
  },

  handleGoogleCallback: async (code: string): Promise<TokenResponse> => {
    const response = await apiClient.post<TokenResponse>('/auth/google/callback', { code });
    return response.data;
  },

  getMe: async (): Promise<User> => {
    const response = await apiClient.get<User>('/auth/me');
    return response.data;
  },

  refreshToken: async (refreshToken: string): Promise<TokenResponse> => {
    const response = await apiClient.post<TokenResponse>('/auth/refresh', {
      refresh_token: refreshToken,
    });
    return response.data;
  },

  logout: async (): Promise<void> => {
    await apiClient.post('/auth/logout');
  },
};
