import { apiClient } from './api';
import { EmailMessage, PaginatedEmailResponse } from '../types';

export const gmailApi = {
  getMessages: async (
    page: number = 1,
    size: number = 20,
    search?: string
  ): Promise<PaginatedEmailResponse> => {
    const params: Record<string, any> = { page, size };
    if (search && search.trim() !== '') {
      params.search = search.trim();
    }
    const response = await apiClient.get<PaginatedEmailResponse>('/gmail/messages', { params });
    return response.data;
  },

  syncMessages: async (limit: number = 20): Promise<{ count: number; message: string }> => {
    const response = await apiClient.post<{ count: number; message: string }>('/gmail/sync', null, {
      params: { limit },
    });
    return response.data;
  },

  getMessage: async (id: string): Promise<EmailMessage> => {
    const response = await apiClient.get<EmailMessage>(`/gmail/messages/${id}`);
    return response.data;
  },
};
