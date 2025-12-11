import { api } from './client';
import type { AuthResponse, LoginCredentials, User } from '$lib/types';

export const authApi = {
	async login(credentials: LoginCredentials): Promise<AuthResponse> {
		const response = await api.post<{
			token: string;
			refresh_token: string;
			user: User;
			expires_in: number;
		}>('/auth/login', credentials);

		api.setToken(response.token);
		return response;
	},

	async logout(): Promise<void> {
		await api.post('/auth/logout');
		api.setToken(null);
	},

	async getMe(): Promise<User> {
		return api.get<User>('/auth/me');
	},

	async refreshToken(refreshToken: string): Promise<AuthResponse> {
		const response = await api.post<AuthResponse>('/auth/refresh', {
			refresh_token: refreshToken
		});

		api.setToken(response.token);
		return response;
	}
};
