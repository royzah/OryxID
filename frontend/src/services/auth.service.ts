import { apiClient } from '@/lib/api';
import type { AuthResponse, LoginCredentials, User } from '@/types';

export const authService = {
  login: async (credentials: LoginCredentials): Promise<AuthResponse> => {
    const { data } = await apiClient.post('/auth/login', credentials);
    return data;
  },

  logout: async (): Promise<void> => {
    try {
      // First get CSRF token if CSRF is enabled
      const { data: csrfData } = await apiClient.get('/csrf-token');

      // Then call logout with CSRF token
      await apiClient.post('/auth/logout', {}, {
        headers: {
          'X-CSRF-Token': csrfData.csrf_token
        }
      });
    } catch (_error) {
      // If CSRF endpoint fails, try logout without token
      // This handles cases where CSRF might be disabled
      try {
        await apiClient.post('/auth/logout');
      } catch {
        // Ignore errors - we're logging out anyway
      }
    }
  },

  getMe: async (): Promise<User> => {
    const { data } = await apiClient.get('/auth/me');
    return data;
  },

  refreshToken: async (refreshToken: string): Promise<AuthResponse> => {
    const { data } = await apiClient.post('/auth/refresh', { refreshToken });
    return data;
  },
};