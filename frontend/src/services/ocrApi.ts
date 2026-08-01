import { apiClient } from './api';
import { OCRAnalysisResponse } from '../types';

export const ocrApi = {
  scanImage: async (file: File): Promise<OCRAnalysisResponse> => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await apiClient.post<OCRAnalysisResponse>('/ocr/scan', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
};
