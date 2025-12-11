import { writable, derived, get } from 'svelte/store';
import { browser } from '$app/environment';
import { goto } from '$app/navigation';
import { authApi, api } from '$lib/api';
import type { User, LoginCredentials } from '$lib/types';

interface AuthState {
	user: User | null;
	token: string | null;
	refreshToken: string | null;
	isLoading: boolean;
	isInitialized: boolean;
}

const initialState: AuthState = {
	user: null,
	token: null,
	refreshToken: null,
	isLoading: false,
	isInitialized: false
};

function createAuthStore() {
	const { subscribe, set, update } = writable<AuthState>(initialState);

	// Initialize from localStorage if in browser
	if (browser) {
		const storedToken = localStorage.getItem('token');
		const storedRefreshToken = localStorage.getItem('refreshToken');
		const storedUser = localStorage.getItem('user');

		if (storedToken) {
			api.setToken(storedToken);
			update((state) => ({
				...state,
				token: storedToken,
				refreshToken: storedRefreshToken,
				user: storedUser ? JSON.parse(storedUser) : null,
				isInitialized: true
			}));
		} else {
			update((state) => ({ ...state, isInitialized: true }));
		}
	}

	return {
		subscribe,

		async login(credentials: LoginCredentials) {
			update((state) => ({ ...state, isLoading: true }));

			try {
				const response = await authApi.login(credentials);

				// Set token in API client (authApi.login also does this, but we do it here too for test compatibility)
				api.setToken(response.token);

				if (browser) {
					localStorage.setItem('token', response.token);
					localStorage.setItem('refreshToken', response.refresh_token);
					localStorage.setItem('user', JSON.stringify(response.user));
				}

				update((state) => ({
					...state,
					user: response.user,
					token: response.token,
					refreshToken: response.refresh_token,
					isLoading: false
				}));

				return response;
			} catch (error) {
				update((state) => ({ ...state, isLoading: false }));
				throw error;
			}
		},

		async logout() {
			try {
				await authApi.logout();
			} catch {
				// Ignore logout errors
			}

			if (browser) {
				localStorage.removeItem('token');
				localStorage.removeItem('refreshToken');
				localStorage.removeItem('user');
			}

			api.setToken(null);
			set({ ...initialState, isInitialized: true });
			goto('/login');
		},

		async refreshToken() {
			const state = get({ subscribe });
			if (!state.refreshToken) {
				throw new Error('No refresh token available');
			}

			try {
				const response = await authApi.refreshToken(state.refreshToken);

				// Set token in API client
				api.setToken(response.token);

				if (browser) {
					localStorage.setItem('token', response.token);
					localStorage.setItem('refreshToken', response.refresh_token);
					localStorage.setItem('user', JSON.stringify(response.user));
				}

				update((s) => ({
					...s,
					user: response.user,
					token: response.token,
					refreshToken: response.refresh_token
				}));

				return response;
			} catch {
				// If refresh fails, clear auth state
				this.clearAuth();
			}
		},

		setUser(user: User) {
			if (browser) {
				localStorage.setItem('user', JSON.stringify(user));
			}
			update((state) => ({ ...state, user }));
		},

		clearAuth() {
			if (browser) {
				localStorage.removeItem('token');
				localStorage.removeItem('refreshToken');
				localStorage.removeItem('user');
			}
			api.setToken(null);
			set({ ...initialState, isInitialized: true });
		}
	};
}

export const auth = createAuthStore();

export const isAuthenticated = derived(auth, ($auth) => !!$auth.token && !!$auth.user);

export const currentUser = derived(auth, ($auth) => $auth.user);

export const isAdmin = derived(auth, ($auth) => $auth.user?.is_admin ?? false);
