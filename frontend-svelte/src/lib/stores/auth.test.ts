import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';

// Mock the API before importing auth store
vi.mock('$lib/api', () => ({
	authApi: {
		login: vi.fn(),
		logout: vi.fn(),
		refreshToken: vi.fn(),
		me: vi.fn()
	},
	api: {
		setToken: vi.fn()
	}
}));

describe('Auth Store', () => {
	let auth: typeof import('./auth').auth;
	let isAuthenticated: typeof import('./auth').isAuthenticated;
	let authApi: typeof import('$lib/api').authApi;
	let api: typeof import('$lib/api').api;

	beforeEach(async () => {
		vi.resetModules();
		localStorage.clear();

		// Re-import to get fresh store
		const authModule = await import('./auth');
		auth = authModule.auth;
		isAuthenticated = authModule.isAuthenticated;

		const apiModule = await import('$lib/api');
		authApi = apiModule.authApi;
		api = apiModule.api;
	});

	afterEach(() => {
		vi.clearAllMocks();
	});

	describe('initial state', () => {
		it('should have null token and user initially', () => {
			const state = get(auth);
			expect(state.token).toBeNull();
			expect(state.user).toBeNull();
		});

		it('should not be authenticated initially', () => {
			expect(get(isAuthenticated)).toBe(false);
		});
	});

	describe('login', () => {
		it('should set token and user on successful login', async () => {
			const mockResponse = {
				token: 'access-token',
				refresh_token: 'refresh-token',
				user: {
					id: '1',
					username: 'testuser',
					email: 'test@example.com',
					is_admin: true,
					is_active: true,
					email_verified: true,
					created_at: '2024-01-01',
					updated_at: '2024-01-01'
				},
				expires_in: 3600
			};

			vi.mocked(authApi.login).mockResolvedValueOnce(mockResponse);

			await auth.login({ username: 'testuser', password: 'password123' });

			const state = get(auth);
			expect(state.token).toBe('access-token');
			expect(state.user).toEqual(mockResponse.user);
			expect(api.setToken).toHaveBeenCalledWith('access-token');
			expect(get(isAuthenticated)).toBe(true);
		});

		it('should store auth data in localStorage', async () => {
			const mockResponse = {
				token: 'access-token',
				refresh_token: 'refresh-token',
				user: {
					id: '1',
					username: 'testuser',
					email: 'test@example.com',
					is_admin: false,
					is_active: true,
					email_verified: false,
					created_at: '2024-01-01',
					updated_at: '2024-01-01'
				},
				expires_in: 3600
			};

			vi.mocked(authApi.login).mockResolvedValueOnce(mockResponse);

			await auth.login({ username: 'testuser', password: 'password' });

			expect(localStorage.setItem).toHaveBeenCalled();
		});

		it('should throw error on failed login', async () => {
			vi.mocked(authApi.login).mockRejectedValueOnce(new Error('Invalid credentials'));

			await expect(auth.login({ username: 'bad', password: 'bad' })).rejects.toThrow(
				'Invalid credentials'
			);

			expect(get(isAuthenticated)).toBe(false);
		});
	});

	describe('logout', () => {
		it('should clear token and user on logout', async () => {
			// First login
			const mockResponse = {
				token: 'token',
				refresh_token: 'refresh',
				user: {
					id: '1',
					username: 'test',
					email: 'test@test.com',
					is_admin: false,
					is_active: true,
					email_verified: false,
					created_at: '',
					updated_at: ''
				},
				expires_in: 3600
			};
			vi.mocked(authApi.login).mockResolvedValueOnce(mockResponse);
			await auth.login({ username: 'test', password: 'test' });

			// Then logout
			vi.mocked(authApi.logout).mockResolvedValueOnce(undefined);
			await auth.logout();

			const state = get(auth);
			expect(state.token).toBeNull();
			expect(state.user).toBeNull();
			expect(api.setToken).toHaveBeenLastCalledWith(null);
			expect(get(isAuthenticated)).toBe(false);
		});

		it('should clear localStorage on logout', async () => {
			vi.mocked(authApi.logout).mockResolvedValueOnce(undefined);
			await auth.logout();

			expect(localStorage.removeItem).toHaveBeenCalled();
		});

		it('should still clear local state if API logout fails', async () => {
			// Setup logged in state
			const mockResponse = {
				token: 'token',
				refresh_token: 'refresh',
				user: {
					id: '1',
					username: 'test',
					email: 'test@test.com',
					is_admin: false,
					is_active: true,
					email_verified: false,
					created_at: '',
					updated_at: ''
				},
				expires_in: 3600
			};
			vi.mocked(authApi.login).mockResolvedValueOnce(mockResponse);
			await auth.login({ username: 'test', password: 'test' });

			// Logout fails at API level
			vi.mocked(authApi.logout).mockRejectedValueOnce(new Error('Network error'));
			await auth.logout();

			// Local state should still be cleared
			const state = get(auth);
			expect(state.token).toBeNull();
			expect(state.user).toBeNull();
		});
	});

	describe('refreshToken', () => {
		it('should update token on successful refresh', async () => {
			// Setup initial state
			const initialResponse = {
				token: 'old-token',
				refresh_token: 'refresh-token',
				user: {
					id: '1',
					username: 'test',
					email: 'test@test.com',
					is_admin: false,
					is_active: true,
					email_verified: false,
					created_at: '',
					updated_at: ''
				},
				expires_in: 3600
			};
			vi.mocked(authApi.login).mockResolvedValueOnce(initialResponse);
			await auth.login({ username: 'test', password: 'test' });

			// Refresh token
			const refreshResponse = {
				token: 'new-token',
				refresh_token: 'new-refresh-token',
				user: initialResponse.user,
				expires_in: 3600
			};
			vi.mocked(authApi.refreshToken).mockResolvedValueOnce(refreshResponse);
			await auth.refreshToken();

			const state = get(auth);
			expect(state.token).toBe('new-token');
			expect(api.setToken).toHaveBeenLastCalledWith('new-token');
		});

		it('should clear state if refresh fails', async () => {
			// Setup initial state
			const initialResponse = {
				token: 'old-token',
				refresh_token: 'refresh-token',
				user: {
					id: '1',
					username: 'test',
					email: 'test@test.com',
					is_admin: false,
					is_active: true,
					email_verified: false,
					created_at: '',
					updated_at: ''
				},
				expires_in: 3600
			};
			vi.mocked(authApi.login).mockResolvedValueOnce(initialResponse);
			await auth.login({ username: 'test', password: 'test' });

			// Refresh fails
			vi.mocked(authApi.refreshToken).mockRejectedValueOnce(new Error('Refresh failed'));
			await auth.refreshToken();

			const state = get(auth);
			expect(state.token).toBeNull();
			expect(state.user).toBeNull();
		});
	});

	describe('setUser', () => {
		it('should update user data', () => {
			const user = {
				id: '1',
				username: 'updated',
				email: 'updated@test.com',
				is_admin: true,
				is_active: true,
				email_verified: true,
				created_at: '2024-01-01',
				updated_at: '2024-01-02'
			};

			auth.setUser(user);

			const state = get(auth);
			expect(state.user).toEqual(user);
		});
	});

	describe('clearAuth', () => {
		it('should clear all auth state', () => {
			// Set up some state
			auth.setUser({
				id: '1',
				username: 'test',
				email: 'test@test.com',
				is_admin: false,
				is_active: true,
				email_verified: false,
				created_at: '',
				updated_at: ''
			});

			auth.clearAuth();

			const state = get(auth);
			expect(state.token).toBeNull();
			expect(state.user).toBeNull();
			expect(state.refreshToken).toBeNull();
		});
	});

	describe('isAuthenticated derived store', () => {
		it('should be true when token and user are present', async () => {
			const mockResponse = {
				token: 'token',
				refresh_token: 'refresh',
				user: {
					id: '1',
					username: 'test',
					email: 'test@test.com',
					is_admin: false,
					is_active: true,
					email_verified: false,
					created_at: '',
					updated_at: ''
				},
				expires_in: 3600
			};
			vi.mocked(authApi.login).mockResolvedValueOnce(mockResponse);
			await auth.login({ username: 'test', password: 'test' });

			expect(get(isAuthenticated)).toBe(true);
		});

		it('should be false when token is missing', () => {
			expect(get(isAuthenticated)).toBe(false);
		});

		it('should be false after logout', async () => {
			const mockResponse = {
				token: 'token',
				refresh_token: 'refresh',
				user: {
					id: '1',
					username: 'test',
					email: 'test@test.com',
					is_admin: false,
					is_active: true,
					email_verified: false,
					created_at: '',
					updated_at: ''
				},
				expires_in: 3600
			};
			vi.mocked(authApi.login).mockResolvedValueOnce(mockResponse);
			await auth.login({ username: 'test', password: 'test' });

			vi.mocked(authApi.logout).mockResolvedValueOnce(undefined);
			await auth.logout();

			expect(get(isAuthenticated)).toBe(false);
		});
	});
});
