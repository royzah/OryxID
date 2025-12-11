import { api } from './client';
import type { Statistics } from '$lib/types';

export const statsApi = {
	async get(): Promise<Statistics> {
		return api.get<Statistics>('/stats');
	}
};
