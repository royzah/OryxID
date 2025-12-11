import { api } from './client';
import type { User, CreateUserRequest, UpdateUserRequest } from '$lib/types';

export const usersApi = {
	async list(search?: string): Promise<User[]> {
		return api.get<User[]>('/users', { search });
	},

	async get(id: string): Promise<User> {
		return api.get<User>(`/users/${id}`);
	},

	async create(data: CreateUserRequest): Promise<User> {
		return api.post<User>('/users', data);
	},

	async update(id: string, data: UpdateUserRequest): Promise<User> {
		return api.put<User>(`/users/${id}`, data);
	},

	async delete(id: string): Promise<void> {
		return api.delete(`/users/${id}`);
	}
};
