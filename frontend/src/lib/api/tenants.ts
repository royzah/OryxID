import { api } from './client';
import type { Tenant, CreateTenantRequest, UpdateTenantRequest, Application } from '$lib/types';

export const tenantsApi = {
	async list(search?: string): Promise<Tenant[]> {
		return api.get<Tenant[]>('/tenants', { search });
	},

	async get(id: string): Promise<Tenant> {
		return api.get<Tenant>(`/tenants/${id}`);
	},

	async create(data: CreateTenantRequest): Promise<Tenant> {
		return api.post<Tenant>('/tenants', data);
	},

	async update(id: string, data: UpdateTenantRequest): Promise<Tenant> {
		return api.put<Tenant>(`/tenants/${id}`, data);
	},

	async delete(id: string): Promise<void> {
		return api.delete(`/tenants/${id}`);
	},

	async suspend(id: string): Promise<Tenant> {
		return api.post<Tenant>(`/tenants/${id}/suspend`, {});
	},

	async activate(id: string): Promise<Tenant> {
		return api.post<Tenant>(`/tenants/${id}/activate`, {});
	},

	async getApplications(id: string): Promise<Application[]> {
		return api.get<Application[]>(`/tenants/${id}/applications`);
	},

	async assignApplication(tenantId: string, applicationId: string): Promise<void> {
		return api.post(`/tenants/${tenantId}/applications/${applicationId}`, {});
	}
};
