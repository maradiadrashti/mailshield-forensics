import { apiClient } from './api';
import {
  ForensicHeaderResponse,
  Investigation,
  InvestigationListResponse,
  OpenInvestigationRequest,
} from '../types';

export const forensicsApi = {
  getForensicHeaders: async (emailId: string): Promise<ForensicHeaderResponse> => {
    const response = await apiClient.get<ForensicHeaderResponse>(`/forensics/emails/${emailId}/headers`);
    return response.data;
  },

  getInvestigations: async (statusFilter?: string, search?: string): Promise<InvestigationListResponse> => {
    const params: Record<string, any> = {};
    if (statusFilter && statusFilter.trim()) params.status_filter = statusFilter.trim();
    if (search && search.trim()) params.search = search.trim();
    const response = await apiClient.get<InvestigationListResponse>('/forensics/investigations', { params });
    return response.data;
  },

  openInvestigation: async (emailId: string, notes?: string): Promise<Investigation> => {
    const payload: OpenInvestigationRequest = { email_id: emailId, notes };
    const response = await apiClient.post<Investigation>('/forensics/investigations', payload);
    return response.data;
  },

  getInvestigation: async (investigationId: string): Promise<Investigation> => {
    const response = await apiClient.get<Investigation>(`/forensics/investigations/${investigationId}`);
    return response.data;
  },
};
