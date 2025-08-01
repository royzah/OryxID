import { apiClient } from '@/lib/api';
import type {
  Scope,
  CreateScopeDto,
  UpdateScopeDto,
  PaginatedResponse,
  QueryParams,
} from '@/types';

export const scopesService = {
  getAll: async (params?: QueryParams): Promise<PaginatedResponse<Scope>> => {
    const { data } = await apiClient.get('/api/v1/scopes', { params });
    return data;
  },

  getById: async (id: string): Promise<Scope> => {
    const { data } = await apiClient.get(`/api/v1/scopes/${id}`);
    return data;
  },

  create: async (dto: CreateScopeDto): Promise<Scope> => {
    const { data } = await apiClient.post('/api/v1/scopes', dto);
    return data;
  },

  update: async (id: string, dto: UpdateScopeDto): Promise<Scope> => {
    const { data } = await apiClient.put(`/api/v1/scopes/${id}`, dto);
    return data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/scopes/${id}`);
  },
};
