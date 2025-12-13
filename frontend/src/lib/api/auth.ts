import { api } from './client';
import type { AuthResponse, LoginCredentials, User } from '$lib/types';

export interface MFARequiredResponse {
	mfa_required: true;
	mfa_token: string;
}

export type LoginResponse = AuthResponse | MFARequiredResponse;

export function isMFARequired(response: LoginResponse): response is MFARequiredResponse {
	return 'mfa_required' in response && response.mfa_required === true;
}

export const authApi = {
	async login(credentials: LoginCredentials): Promise<LoginResponse> {
		const response = await api.postDirect<LoginResponse>('/auth/login', credentials);

		// Only set token if not MFA required
		if (!isMFARequired(response)) {
			api.setToken(response.token);
		}
		return response;
	},

	async verifyMFA(mfaToken: string, code: string): Promise<AuthResponse> {
		const response = await api.postDirect<AuthResponse>('/auth/login/mfa', {
			mfa_token: mfaToken,
			code
		});

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
