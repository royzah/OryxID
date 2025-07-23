import { create } from "zustand";
import { persist } from "zustand/middleware";
import api from "../services/api";
import type { User } from "../types";

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
  setToken: (token: string) => void;
}

const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,

      setToken: (token: string) => {
        set({ token });
        api.defaults.headers.common["Authorization"] = `Bearer ${token}`;
      },

      login: async (username: string, password: string) => {
        set({ isLoading: true });
        try {
          const response = await api.post("/auth/login", {
            username,
            password,
          });
          const { token, user } = response.data;

          set({
            token,
            user,
            isAuthenticated: true,
            isLoading: false,
          });

          api.defaults.headers.common["Authorization"] = `Bearer ${token}`;
        } catch (error) {
          set({ isLoading: false });
          throw error;
        }
      },

      logout: async () => {
        try {
          await api.post("/auth/logout");
        } catch {
          // Ignore logout errors
        } finally {
          set({
            user: null,
            token: null,
            isAuthenticated: false,
          });
          delete api.defaults.headers.common["Authorization"];
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
          api.defaults.headers.common["Authorization"] = `Bearer ${token}`;
          const response = await api.get("/auth/me");
          set({
            user: response.data,
            isAuthenticated: true,
            isLoading: false,
          });
        } catch {
          set({
            user: null,
            token: null,
            isAuthenticated: false,
            isLoading: false,
          });
          delete api.defaults.headers.common["Authorization"];
        }
      },
    }),
    {
      name: "auth-storage",
      partialize: (state) => ({ token: state.token }),
    },
  ),
);

export default useAuthStore;
