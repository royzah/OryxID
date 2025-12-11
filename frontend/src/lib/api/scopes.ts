import { api } from './client';
import type { Scope, CreateScopeRequest, UpdateScopeRequest } from '$lib/types';

export const scopesApi = {
	async list(): Promise<Scope[]> {
		return api.get<Scope[]>('/scopes');
	},

	async get(id: string): Promise<Scope> {
		return api.get<Scope>(`/scopes/${id}`);
	},

	async create(data: CreateScopeRequest): Promise<Scope> {
		return api.post<Scope>('/scopes', data);
	},

	async update(id: string, data: UpdateScopeRequest): Promise<Scope> {
		return api.put<Scope>(`/scopes/${id}`, data);
	},

	async delete(id: string): Promise<void> {
		return api.delete(`/scopes/${id}`);
	}
};
