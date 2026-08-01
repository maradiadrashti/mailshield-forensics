import { apiClient } from './api';
import { URLSingleAnalysis } from '../types';

export const urlAnalysisApi = {
  scanUrl: async (url: string): Promise<URLSingleAnalysis> => {
    const response = await apiClient.post<URLSingleAnalysis>('/analysis/url/scan', { url });
    return response.data;
  },
};
