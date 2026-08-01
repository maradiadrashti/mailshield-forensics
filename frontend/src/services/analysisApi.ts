import { apiClient } from './api';
import { AnalysisResult, BatchAnalysisResponse } from '../types';

export const analysisApi = {
  analyzeEmail: async (emailId: string): Promise<AnalysisResult> => {
    const response = await apiClient.post<AnalysisResult>(`/analysis/email/${emailId}`);
    return response.data;
  },

  getAnalysis: async (emailId: string): Promise<AnalysisResult> => {
    const response = await apiClient.get<AnalysisResult>(`/analysis/email/${emailId}`);
    return response.data;
  },

  batchAnalyze: async (): Promise<BatchAnalysisResponse> => {
    const response = await apiClient.post<BatchAnalysisResponse>('/analysis/batch');
    return response.data;
  },
};
