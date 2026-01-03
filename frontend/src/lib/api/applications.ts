import { api } from './client';
import type { Application, CreateApplicationRequest, UpdateApplicationRequest } from '$lib/types';

export const applicationsApi = {
	async list(search?: string): Promise<Application[]> {
		return api.get<Application[]>('/applications', { search });
	},

	async get(id: string): Promise<Application> {
		return api.get<Application>(`/applications/${id}`);
	},

	async create(data: CreateApplicationRequest): Promise<Application> {
		return api.post<Application>('/applications', data);
	},

	async update(id: string, data: UpdateApplicationRequest): Promise<Application> {
		return api.put<Application>(`/applications/${id}`, data);
	},

	async delete(id: string): Promise<void> {
		return api.delete(`/applications/${id}`);
	},

	async rotateSecret(id: string): Promise<{ client_id: string; client_secret: string; message: string }> {
		return api.post(`/applications/${id}/rotate-secret`, {});
	}
};
