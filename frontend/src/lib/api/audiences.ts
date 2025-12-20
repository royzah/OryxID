import { api } from './client';
import type { Audience, CreateAudienceRequest, UpdateAudienceRequest } from '$lib/types';

export const audiencesApi = {
	async list(): Promise<Audience[]> {
		return api.get<Audience[]>('/audiences');
	},

	async get(id: string): Promise<Audience> {
		return api.get<Audience>(`/audiences/${id}`);
	},

	async create(data: CreateAudienceRequest): Promise<Audience> {
		return api.post<Audience>('/audiences', data);
	},

	async update(id: string, data: UpdateAudienceRequest): Promise<Audience> {
		return api.put<Audience>(`/audiences/${id}`, data);
	},

	async delete(id: string): Promise<void> {
		return api.delete(`/audiences/${id}`);
	}
};
