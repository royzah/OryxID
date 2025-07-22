import axios, { AxiosInstance, AxiosError } from 'axios';
import { toast } from '../components/ui/use-toast';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:9000';

const api: AxiosInstance = axios.create({
    baseURL: API_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Request interceptor to add auth token
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        if (token && config.headers) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Response interceptor for error handling
api.interceptors.response.use(
    (response) => response,
    (error: AxiosError) => {
        if (error.response) {
            switch (error.response.status) {
                case 401:
                    // Unauthorized - redirect to login
                    localStorage.removeItem('token');
                    window.location.href = '/login';
                    break;
                case 403:
                    toast({
                        title: 'Access Denied',
                        description: 'You do not have permission to perform this action.',
                        variant: 'destructive',
                    });
                    break;
                case 404:
                    toast({
                        title: 'Not Found',
                        description: 'The requested resource was not found.',
                        variant: 'destructive',
                    });
                    break;
                case 500:
                    toast({
                        title: 'Server Error',
                        description: 'An unexpected error occurred. Please try again later.',
                        variant: 'destructive',
                    });
                    break;
                default:
                    const errorData = error.response.data as { error?: string; message?: string };
                    toast({
                        title: 'Error',
                        description: errorData.error || errorData.message || 'An error occurred',
                        variant: 'destructive',
                    });
            }
        } else if (error.request) {
            toast({
                title: 'Network Error',
                description: 'Unable to connect to the server. Please check your connection.',
                variant: 'destructive',
            });
        }
        return Promise.reject(error);
    }
);

export default api;

// API service functions
export const authService = {
    login: (username: string, password: string) =>
        api.post('/auth/login', { username, password }),

    logout: () => api.post('/auth/logout'),

    me: () => api.get('/auth/me'),
};

export const applicationService = {
    list: (params?: { search?: string }) =>
        api.get('/api/v1/applications', { params }),

    create: (data: any) =>
        api.post('/api/v1/applications', data),

    get: (id: string) =>
        api.get(`/api/v1/applications/${id}`),

    update: (id: string, data: any) =>
        api.put(`/api/v1/applications/${id}`, data),

    delete: (id: string) =>
        api.delete(`/api/v1/applications/${id}`),
};

export const scopeService = {
    list: () => api.get('/api/v1/scopes'),

    create: (data: any) =>
        api.post('/api/v1/scopes', data),

    get: (id: string) =>
        api.get(`/api/v1/scopes/${id}`),

    update: (id: string, data: any) =>
        api.put(`/api/v1/scopes/${id}`, data),

    delete: (id: string) =>
        api.delete(`/api/v1/scopes/${id}`),
};

export const audienceService = {
    list: () => api.get('/api/v1/audiences'),

    create: (data: any) =>
        api.post('/api/v1/audiences', data),

    get: (id: string) =>
        api.get(`/api/v1/audiences/${id}`),

    update: (id: string, data: any) =>
        api.put(`/api/v1/audiences/${id}`, data),

    delete: (id: string) =>
        api.delete(`/api/v1/audiences/${id}`),
};

export const userService = {
    list: (params?: { search?: string }) =>
        api.get('/api/v1/users', { params }),

    create: (data: any) =>
        api.post('/api/v1/users', data),

    get: (id: string) =>
        api.get(`/api/v1/users/${id}`),

    update: (id: string, data: any) =>
        api.put(`/api/v1/users/${id}`, data),

    delete: (id: string) =>
        api.delete(`/api/v1/users/${id}`),
};

export const auditService = {
    list: (params?: {
        user_id?: string;
        application_id?: string;
        action?: string;
        page?: number;
        limit?: number;
    }) => api.get('/api/v1/audit-logs', { params }),
};

export const statsService = {
    get: () => api.get('/api/v1/stats'),
};