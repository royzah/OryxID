import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import type { User } from '@/types';
import { authService } from '@/services/auth.service';
import { AxiosError } from 'axios';

interface AuthState {
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  // Actions
  login: (auth: { username: string; password: string }) => Promise<void>;
  logout: () => void;
  refreshTokenAction: () => Promise<void>;
  checkAuth: () => Promise<void>;
  clearError: () => void;
}

export const useAuthStore = create<AuthState>()(
  devtools(
    persist(
      (set, get) => ({
        user: null,
        token: null,
        refreshToken: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,

        login: async (credentials) => {
          set({ isLoading: true, error: null });
          try {
            const response = await authService.login(credentials);

            set({
              user: response.user,
              token: response.token,
              refreshToken: response.refreshToken,
              isAuthenticated: true,
              isLoading: false,
            });

            // Set token expiry timer
            const expiresIn = response.expiresIn * 1000; // Convert to milliseconds
            setTimeout(() => {
              get().refreshTokenAction();
            }, expiresIn - 60000); // Refresh 1 minute before expiry
          } catch (error) {
            let errorMessage = 'Login failed';

            if (error instanceof AxiosError && error.response?.data) {
              const data = error.response.data;
              if (typeof data === 'object' && 'message' in data) {
                errorMessage = data.message as string;
              }
            } else if (error instanceof Error) {
              errorMessage = error.message;
            }

            set({
              error: errorMessage,
              isLoading: false,
            });
            throw error;
          }
        },

        logout: () => {
          // Call logout API if needed
          authService.logout().catch(() => {});

          set({
            user: null,
            token: null,
            refreshToken: null,
            isAuthenticated: false,
            error: null,
          });
        },

        refreshTokenAction: async () => {
          const refreshToken = get().refreshToken;
          if (!refreshToken) {
            get().logout();
            return;
          }

          try {
            const response = await authService.refreshToken(refreshToken);

            set({
              token: response.token,
              refreshToken: response.refreshToken,
            });

            // Set new token expiry timer
            const expiresIn = response.expiresIn * 1000;
            setTimeout(() => {
              get().refreshTokenAction();
            }, expiresIn - 60000);
          } catch {
            get().logout();
          }
        },

        checkAuth: async () => {
          const token = get().token;
          if (!token) {
            set({ isAuthenticated: false });
            return;
          }

          set({ isLoading: true });
          try {
            const user = await authService.getMe();
            set({
              user,
              isAuthenticated: true,
              isLoading: false,
            });
          } catch {
            get().logout();
          }
        },

        clearError: () => set({ error: null }),
      }),
      {
        name: 'auth-storage',
        partialize: (state) => ({
          token: state.token,
          refreshToken: state.refreshToken,
          user: state.user,
        }),
      },
    ),
  ),
);
