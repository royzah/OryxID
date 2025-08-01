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
  refreshTimer: ReturnType<typeof setTimeout> | null;

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
        refreshTimer: null,

        login: async (credentials) => {
          set({ isLoading: true, error: null });
          try {
            const response = await authService.login(credentials);

            // Clear any existing refresh timer
            const existingTimer = get().refreshTimer;
            if (existingTimer) {
              clearTimeout(existingTimer);
            }

            // Set token expiry timer
            const expiresIn = response.expiresIn * 1000; // Convert to milliseconds
            const timer = setTimeout(() => {
              get().refreshTokenAction();
            }, expiresIn - 60000); // Refresh 1 minute before expiry

            set({
              user: response.user,
              token: response.token,
              refreshToken: response.refreshToken,
              isAuthenticated: true,
              isLoading: false,
              refreshTimer: timer,
            });
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
          // Clear refresh timer
          const timer = get().refreshTimer;
          if (timer) {
            clearTimeout(timer);
          }

          // Only call logout API if we have a token
          const token = get().token;
          if (token) {
            authService.logout().catch(() => {
              // Ignore logout errors - we're logging out anyway
            });
          }

          set({
            user: null,
            token: null,
            refreshToken: null,
            isAuthenticated: false,
            error: null,
            refreshTimer: null,
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

            // Clear existing timer
            const existingTimer = get().refreshTimer;
            if (existingTimer) {
              clearTimeout(existingTimer);
            }

            // Set new token expiry timer
            const expiresIn = response.expiresIn * 1000;
            const timer = setTimeout(() => {
              get().refreshTokenAction();
            }, expiresIn - 60000);

            set({
              token: response.token,
              refreshToken: response.refreshToken,
              refreshTimer: timer,
            });
          } catch {
            // Don't call logout here - it causes the 403 error
            // Just clear the auth state
            set({
              user: null,
              token: null,
              refreshToken: null,
              isAuthenticated: false,
              error: null,
              refreshTimer: null,
            });
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
            // Don't call logout() here to avoid the 403 error
            set({
              user: null,
              token: null,
              refreshToken: null,
              isAuthenticated: false,
              isLoading: false,
              refreshTimer: null,
            });
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