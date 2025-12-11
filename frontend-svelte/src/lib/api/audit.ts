import { api } from './client';
import type { AuditLogsResponse } from '$lib/types';

export const auditApi = {
	async list(params?: {
		page?: number;
		limit?: number;
		user_id?: string;
		application_id?: string;
		action?: string;
	}): Promise<AuditLogsResponse> {
		return api.get<AuditLogsResponse>('/audit-logs', params);
	}
};
