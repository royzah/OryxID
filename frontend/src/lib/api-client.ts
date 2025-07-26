import axios, { AxiosError, AxiosInstance } from "axios";
import { toast } from "@/components/ui/use-toast";

// Extend the axios request config type to include our custom property
declare module "axios" {
  interface InternalAxiosRequestConfig {
    _retry?: boolean;
  }
}

interface ApiError {
  error: string;
  message?: string;
  field?: string;
  code?: string;
}

class ApiClient {
  private client: AxiosInstance;
  private refreshPromise: Promise<void> | null = null;

  constructor() {
    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_URL,
      timeout: 10000,
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        const token = this.getToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error),
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError<ApiError>) => {
        const originalRequest = error.config;

        // Handle 401 with token refresh
        if (
          error.response?.status === 401 &&
          originalRequest &&
          !originalRequest._retry
        ) {
          originalRequest._retry = true;

          if (!this.refreshPromise) {
            this.refreshPromise = this.refreshToken();
          }

          try {
            await this.refreshPromise;
            this.refreshPromise = null;
            return this.client(originalRequest);
          } catch (refreshError) {
            this.handleAuthError();
            return Promise.reject(refreshError);
          }
        }

        this.handleApiError(error);
        return Promise.reject(error);
      },
    );
  }

  private getToken(): string | null {
    return localStorage.getItem("token");
  }

  private async refreshToken(): Promise<void> {
    try {
      const refreshToken = localStorage.getItem("refreshToken");
      if (!refreshToken) throw new Error("No refresh token");

      const response = await this.client.post("/auth/refresh", {
        refresh_token: refreshToken,
      });

      const { token, refresh_token } = response.data;
      localStorage.setItem("token", token);
      localStorage.setItem("refreshToken", refresh_token);
    } catch (error) {
      throw error;
    }
  }

  private handleAuthError() {
    localStorage.removeItem("token");
    localStorage.removeItem("refreshToken");
    window.location.href = "/login";
  }

  private handleApiError(error: AxiosError<ApiError>) {
    if (!error.response) {
      toast({
        title: "Network Error",
        description: "Unable to connect to the server",
        variant: "destructive",
      });
      return;
    }

    const { status, data } = error.response;
    const message = data.message || data.error || "An error occurred";

    switch (status) {
      case 400:
        toast({
          title: "Invalid Request",
          description: message,
          variant: "destructive",
        });
        break;
      case 403:
        toast({
          title: "Access Denied",
          description: "You do not have permission to perform this action",
          variant: "destructive",
        });
        break;
      case 404:
        toast({
          title: "Not Found",
          description: "The requested resource was not found",
          variant: "destructive",
        });
        break;
      case 422:
        toast({
          title: "Validation Error",
          description: message,
          variant: "destructive",
        });
        break;
      case 429:
        toast({
          title: "Too Many Requests",
          description: "Please slow down and try again later",
          variant: "destructive",
        });
        break;
      case 500:
        toast({
          title: "Server Error",
          description: "An unexpected error occurred",
          variant: "destructive",
        });
        break;
    }
  }

  get instance() {
    return this.client;
  }
}

export const apiClient = new ApiClient();
