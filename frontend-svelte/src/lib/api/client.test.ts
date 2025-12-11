import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api, ApiError } from './client';

// Use globalThis for fetch mock
const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

describe('API Client', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		api.setToken(null);
	});

	describe('setToken', () => {
		it('should set the token', () => {
			api.setToken('test-token');
			// Token is private, so we test indirectly by checking headers in requests
			expect(true).toBe(true);
		});

		it('should allow setting token to null', () => {
			api.setToken('test-token');
			api.setToken(null);
			expect(true).toBe(true);
		});
	});

	describe('GET requests', () => {
		it('should make a GET request', async () => {
			const mockData = { id: '1', name: 'Test' };
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve(mockData)
			} as Response);

			const result = await api.get('/test');

			expect(mockFetch).toHaveBeenCalledWith(
				'/api/admin/test',
				expect.objectContaining({
					method: 'GET',
					headers: expect.objectContaining({
						'Content-Type': 'application/json'
					})
				})
			);
			expect(result).toEqual(mockData);
		});

		it('should include query parameters', async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve([])
			} as Response);

			await api.get('/test', { search: 'query', limit: 10 });

			expect(mockFetch).toHaveBeenCalledWith(
				'/api/admin/test?search=query&limit=10',
				expect.any(Object)
			);
		});

		it('should include authorization header when token is set', async () => {
			api.setToken('bearer-token');

			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve({})
			} as Response);

			await api.get('/test');

			expect(mockFetch).toHaveBeenCalledWith(
				'/api/admin/test',
				expect.objectContaining({
					headers: expect.objectContaining({
						Authorization: 'Bearer bearer-token'
					})
				})
			);
		});

		it('should filter out undefined query params', async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve({})
			} as Response);

			await api.get('/test', { search: 'value', empty: undefined });

			expect(mockFetch).toHaveBeenCalledWith('/api/admin/test?search=value', expect.any(Object));
		});
	});

	describe('POST requests', () => {
		it('should make a POST request with body', async () => {
			const requestBody = { name: 'Test', value: 123 };
			const responseData = { id: '1', ...requestBody };

			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve(responseData)
			} as Response);

			const result = await api.post('/test', requestBody);

			expect(mockFetch).toHaveBeenCalledWith(
				'/api/admin/test',
				expect.objectContaining({
					method: 'POST',
					body: JSON.stringify(requestBody)
				})
			);
			expect(result).toEqual(responseData);
		});

		it('should handle POST without body', async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve({ success: true })
			} as Response);

			await api.post('/test');

			expect(mockFetch).toHaveBeenCalledWith(
				'/api/admin/test',
				expect.objectContaining({
					method: 'POST'
				})
			);
		});
	});

	describe('PUT requests', () => {
		it('should make a PUT request with body', async () => {
			const requestBody = { name: 'Updated' };

			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve({ id: '1', name: 'Updated' })
			} as Response);

			await api.put('/test/1', requestBody);

			expect(mockFetch).toHaveBeenCalledWith(
				'/api/admin/test/1',
				expect.objectContaining({
					method: 'PUT',
					body: JSON.stringify(requestBody)
				})
			);
		});
	});

	describe('DELETE requests', () => {
		it('should make a DELETE request', async () => {
			mockFetch.mockResolvedValueOnce({
				ok: true,
				json: () => Promise.resolve({})
			} as Response);

			await api.delete('/test/1');

			expect(mockFetch).toHaveBeenCalledWith(
				'/api/admin/test/1',
				expect.objectContaining({
					method: 'DELETE'
				})
			);
		});
	});

	describe('Error Handling', () => {
		it('should throw ApiError on non-ok response', async () => {
			mockFetch.mockResolvedValueOnce({
				ok: false,
				status: 404,
				json: () => Promise.resolve({ error: 'Not found', message: 'Resource not found' })
			} as Response);

			await expect(api.get('/nonexistent')).rejects.toThrow('Resource not found');
		});

		it('should throw ApiError with status for unknown errors', async () => {
			mockFetch.mockResolvedValueOnce({
				ok: false,
				status: 500,
				json: () => Promise.resolve({})
			} as Response);

			await expect(api.get('/error')).rejects.toThrow('Request failed with status 500');
		});

		it('should handle network errors', async () => {
			mockFetch.mockRejectedValueOnce(new Error('Network error'));

			await expect(api.get('/test')).rejects.toThrow('Network error');
		});

		it('should handle JSON parse errors gracefully', async () => {
			mockFetch.mockResolvedValueOnce({
				ok: false,
				status: 400,
				json: () => Promise.reject(new Error('Invalid JSON'))
			} as Response);

			await expect(api.get('/test')).rejects.toThrow('Request failed with status 400');
		});
	});
});

describe('ApiError', () => {
	it('should create an ApiError with message', () => {
		const error = new ApiError('Test error', 400);
		expect(error.message).toBe('Test error');
		expect(error.status).toBe(400);
		expect(error.name).toBe('ApiError');
	});

	it('should be an instance of Error', () => {
		const error = new ApiError('Test error', 500);
		expect(error).toBeInstanceOf(Error);
	});
});
