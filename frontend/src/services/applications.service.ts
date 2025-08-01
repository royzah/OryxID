import { apiClient } from '@/lib/api';
import type {
  Application,
  CreateApplicationDto,
  UpdateApplicationDto,
  PaginatedResponse,
  QueryParams,
} from '@/types';

export const applicationsService = {
  getAll: async (
    params?: QueryParams,
  ): Promise<PaginatedResponse<Application>> => {
    const { data } = await apiClient.get('/api/v1/applications', { params });
    return data;
  },

  getById: async (id: string): Promise<Application> => {
    const { data } = await apiClient.get(`/api/v1/applications/${id}`);
    return data;
  },

  create: async (dto: CreateApplicationDto): Promise<Application> => {
    const { data } = await apiClient.post('/api/v1/applications', dto);
    return data;
  },

  update: async (
    id: string,
    dto: UpdateApplicationDto,
  ): Promise<Application> => {
    const { data } = await apiClient.put(`/api/v1/applications/${id}`, dto);
    return data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/applications/${id}`);
  },

  regenerateSecret: async (id: string): Promise<{ clientSecret: string }> => {
    const { data } = await apiClient.post(
      `/api/v1/applications/${id}/regenerate-secret`,
    );
    return data;
  },
};
