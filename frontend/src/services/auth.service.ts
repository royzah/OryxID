import { apiClient } from '@/lib/api';
import type { AuthResponse, LoginCredentials, User } from '@/types';

export const authService = {
  login: async (credentials: LoginCredentials): Promise<AuthResponse> => {
    const { data } = await apiClient.post('/auth/login', credentials);

    return {
      token: data.token,
      refreshToken: data.refresh_token || data.refreshToken,
      user: data.user,
      expiresIn: data.expiresIn || 3600 // Default to 1 hour if not provided
    };
  },

  logout: async (): Promise<void> => {
    await apiClient.post('/auth/logout');
  },

  getMe: async (): Promise<User> => {
    const { data } = await apiClient.get('/auth/me');
    return data;
  },

  refreshToken: async (refreshToken: string): Promise<AuthResponse> => {
    const { data } = await apiClient.post('/auth/refresh', {
      refresh_token: refreshToken // Backend expects refresh_token, not refreshToken
    });

    return {
      token: data.token,
      refreshToken: data.refresh_token || data.refreshToken,
      user: data.user,
      expiresIn: data.expiresIn || 3600
    };
  },
};