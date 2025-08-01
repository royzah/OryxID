import { apiClient } from '@/lib/api';
import type {
  Statistics,
  AuditLog,
  PaginatedResponse,
  QueryParams,
} from '@/types';

export const statsService = {
  getStatistics: async (): Promise<Statistics> => {
    const { data } = await apiClient.get('/api/v1/stats');
    return data;
  },

  getAuditLogs: async (
    params?: QueryParams & {
      userId?: string;
      action?: string;
      startDate?: string;
      endDate?: string;
    },
  ): Promise<PaginatedResponse<AuditLog>> => {
    const { data } = await apiClient.get('/api/v1/audit-logs', { params });
    return data;
  },

  exportAuditLogs: async (
    params?: QueryParams & {
      userId?: string;
      action?: string;
      startDate?: string;
      endDate?: string;
    },
  ): Promise<Blob> => {
    const { data } = await apiClient.get('/api/v1/audit-logs/export', {
      params,
      responseType: 'blob',
    });
    return data;
  },
};
