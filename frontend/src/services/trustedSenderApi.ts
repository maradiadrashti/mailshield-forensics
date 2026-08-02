import { apiClient } from './api';

export const TRUSTED_SENDERS_CHANGED_EVENT = 'trusted-senders:changed';

const notifyTrustedSendersChanged = () => {
  window.dispatchEvent(new Event(TRUSTED_SENDERS_CHANGED_EVENT));
};

export interface TrustedSender {
  id: string;
  user_id: string;
  type: 'email' | 'domain';
  value: string;
  created_at: string;
}

export const trustedSenderApi = {
  getTrustedSenders: async (): Promise<TrustedSender[]> => {
    const response = await apiClient.get<TrustedSender[]>('/trusted-senders');
    return response.data;
  },
  addTrustedSender: async (data: { type: 'email' | 'domain'; value: string }): Promise<TrustedSender> => {
    const response = await apiClient.post<TrustedSender>('/trusted-senders', data);
    notifyTrustedSendersChanged();
    return response.data;
  },
  deleteTrustedSender: async (id: string): Promise<void> => {
    await apiClient.delete(`/trusted-senders/${id}`);
    notifyTrustedSendersChanged();
  },

  deleteTrustedSenderByValue: async (value: string): Promise<void> => {
    await apiClient.delete(`/trusted-senders/by-value?value=${encodeURIComponent(value)}`);
    notifyTrustedSendersChanged();
  },
};
