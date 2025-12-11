import { api } from './client';
import type { AuthResponse, LoginCredentials, User } from '$lib/types';

export const authApi = {
	async login(credentials: LoginCredentials): Promise<AuthResponse> {
		const response = await api.postDirect<{
			token: string;
			refresh_token: string;
			user: User;
			expires_in: number;
		}>('/auth/login', credentials);

		api.setToken(response.token);
		return response;
	},

	async logout(): Promise<void> {
		await api.postDirect('/auth/logout');
		api.setToken(null);
	},

	async getMe(): Promise<User> {
		return api.getDirect<User>('/auth/me');
	},

	async refreshToken(refreshToken: string): Promise<AuthResponse> {
		const response = await api.postDirect<AuthResponse>('/auth/refresh', {
			refresh_token: refreshToken
		});

		api.setToken(response.token);
		return response;
	}
};
