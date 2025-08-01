import { apiClient } from '@/lib/api';
import type {
  User,
  CreateUserDto,
  UpdateUserDto,
  ChangePasswordDto,
  PaginatedResponse,
  QueryParams,
} from '@/types';

export const usersService = {
  getAll: async (params?: QueryParams): Promise<PaginatedResponse<User>> => {
    const { data } = await apiClient.get('/api/v1/users', { params });
    return data;
  },

  getById: async (id: string): Promise<User> => {
    const { data } = await apiClient.get(`/api/v1/users/${id}`);
    return data;
  },

  create: async (dto: CreateUserDto): Promise<User> => {
    const { data } = await apiClient.post('/api/v1/users', dto);
    return data;
  },

  update: async (id: string, dto: UpdateUserDto): Promise<User> => {
    const { data } = await apiClient.put(`/api/v1/users/${id}`, dto);
    return data;
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/api/v1/users/${id}`);
  },

  changePassword: async (
    userId: string,
    dto: ChangePasswordDto,
  ): Promise<void> => {
    await apiClient.post(`/api/v1/users/${userId}/change-password`, dto);
  },
};
