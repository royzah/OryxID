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

            // Only set timer if we have a valid expiresIn
            let timer = null;
            if (response.expiresIn && response.expiresIn > 0) {
              const expiresIn = response.expiresIn * 1000; // Convert to milliseconds
              timer = setTimeout(
                () => {
                  get()
                    .refreshTokenAction()
                    .catch(() => {
                      // If refresh fails, clear auth state
                      get().logout();
                    });
                },
                Math.max(expiresIn - 60000, 10000),
              ); // Refresh at least 10 seconds before expiry
            }

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
          // Prevent multiple logout calls
          const state = get();
          if (!state.isAuthenticated && !state.token) {
            return;
          }

          // Clear refresh timer
          if (state.refreshTimer) {
            clearTimeout(state.refreshTimer);
          }

          // Clear state first to prevent loops
          set({
            user: null,
            token: null,
            refreshToken: null,
            isAuthenticated: false,
            error: null,
            refreshTimer: null,
          });

          // Then try to call logout API (best effort)
          if (state.token) {
            authService.logout().catch(() => {
              // Ignore logout API errors
            });
          }
        },

        refreshTokenAction: async () => {
          const state = get();

          // Prevent refresh if already logging out
          if (!state.isAuthenticated || !state.refreshToken) {
            return;
          }

          try {
            const response = await authService.refreshToken(state.refreshToken);

            // Clear existing timer
            if (state.refreshTimer) {
              clearTimeout(state.refreshTimer);
            }

            // Set new timer
            let timer = null;
            if (response.expiresIn && response.expiresIn > 0) {
              const expiresIn = response.expiresIn * 1000;
              timer = setTimeout(
                () => {
                  get()
                    .refreshTokenAction()
                    .catch(() => {
                      get().logout();
                    });
                },
                Math.max(expiresIn - 60000, 10000),
              );
            }

            set({
              token: response.token,
              refreshToken: response.refreshToken,
              refreshTimer: timer,
            });
          } catch (_error) {
            // Clear auth state on refresh failure
            get().logout();
          }
        },

        checkAuth: async () => {
          const state = get();

          if (!state.token) {
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
          } catch (_error) {
            // Clear auth state on check failure
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
