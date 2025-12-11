import type { ApiError as ApiErrorType } from '$lib/types';

const API_BASE = '/api/v1';

interface FetchOptions extends RequestInit {
	params?: Record<string, string | number | undefined>;
}

export class ApiError extends Error {
	status: number;

	constructor(message: string, status: number) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
	}
}

class ApiClient {
	private token: string | null = null;

	setToken(token: string | null) {
		this.token = token;
	}

	getToken(): string | null {
		return this.token;
	}

	private async request<T>(endpoint: string, options: FetchOptions = {}, useApiBase = true): Promise<T> {
		const { params, ...fetchOptions } = options;

		let url = useApiBase ? `${API_BASE}${endpoint}` : endpoint;

		if (params) {
			const searchParams = new URLSearchParams();
			Object.entries(params).forEach(([key, value]) => {
				if (value !== undefined) {
					searchParams.append(key, String(value));
				}
			});
			const queryString = searchParams.toString();
			if (queryString) {
				url += `?${queryString}`;
			}
		}

		const headers: Record<string, string> = {
			'Content-Type': 'application/json',
			...(fetchOptions.headers as Record<string, string>)
		};

		if (this.token) {
			headers['Authorization'] = `Bearer ${this.token}`;
		}

		const response = await fetch(url, {
			...fetchOptions,
			headers,
			credentials: 'include'
		});

		if (!response.ok) {
			let error: ApiErrorType;
			try {
				error = await response.json();
			} catch {
				throw new ApiError(`Request failed with status ${response.status}`, response.status);
			}
			throw new ApiError(error.message || error.error || `Request failed with status ${response.status}`, response.status);
		}

		if (response.status === 204) {
			return undefined as T;
		}

		return response.json();
	}

	async get<T>(endpoint: string, params?: Record<string, string | number | undefined>): Promise<T> {
		return this.request<T>(endpoint, { method: 'GET', params });
	}

	async post<T>(endpoint: string, body?: unknown): Promise<T> {
		return this.request<T>(endpoint, {
			method: 'POST',
			body: body ? JSON.stringify(body) : undefined
		});
	}

	async put<T>(endpoint: string, body?: unknown): Promise<T> {
		return this.request<T>(endpoint, {
			method: 'PUT',
			body: body ? JSON.stringify(body) : undefined
		});
	}

	async delete<T>(endpoint: string): Promise<T> {
		return this.request<T>(endpoint, { method: 'DELETE' });
	}

	// Methods for direct paths (without API_BASE prefix)
	async getDirect<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
		return this.request<T>(path, { method: 'GET', params }, false);
	}

	async postDirect<T>(path: string, body?: unknown): Promise<T> {
		return this.request<T>(path, {
			method: 'POST',
			body: body ? JSON.stringify(body) : undefined
		}, false);
	}
}

export const api = new ApiClient();
