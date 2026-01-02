export interface User {
	id: string;
	username: string;
	email: string;
	email_verified: boolean;
	is_active: boolean;
	is_admin: boolean;
	roles?: Role[];
	created_at: string;
	updated_at: string;
}

export interface Role {
	id: string;
	name: string;
	description: string;
	permissions?: Permission[];
}

export interface Permission {
	id: string;
	name: string;
	description: string;
}

export interface Application {
	id: string;
	name: string;
	description: string;
	client_id: string;
	client_secret?: string;
	client_type: 'confidential' | 'public';
	token_endpoint_auth_method: string;
	grant_types: string[];
	response_types: string[];
	redirect_uris: string[];
	post_logout_uris: string[];
	scopes?: Scope[];
	audiences?: Audience[];
	skip_authorization: boolean;
	access_token_lifespan: number;
	refresh_token_lifespan: number;
	owner_id?: string;
	tenant_id?: string;
	tenant?: Tenant;
	created_at: string;
	updated_at: string;
}

export interface Scope {
	id: string;
	name: string;
	description: string;
	is_default: boolean;
	created_at: string;
	updated_at: string;
}

export interface Audience {
	id: string;
	identifier: string;
	name: string;
	description: string;
	scopes?: Scope[];
	created_at: string;
	updated_at: string;
}

export interface AuditLog {
	id: string;
	user_id?: string;
	user?: User;
	application_id?: string;
	application?: Application;
	action: string;
	resource: string;
	resource_id: string;
	ip_address: string;
	user_agent: string;
	status_code: number;
	metadata?: Record<string, unknown>;
	created_at: string;
}

export interface Statistics {
	applications: number;
	users: number;
	scopes: number;
	audiences: number;
	active_tokens: number;
}

export interface LoginCredentials {
	username: string;
	password: string;
}

export interface AuthResponse {
	token: string;
	refresh_token: string;
	user: User;
	expires_in: number;
}

export interface CreateApplicationRequest {
	name: string;
	description?: string;
	client_type: 'confidential' | 'public';
	grant_types: string[];
	response_types?: string[];
	redirect_uris?: string[];
	post_logout_uris?: string[];
	scope_ids?: string[];
	audience_ids?: string[];
	skip_authorization?: boolean;
	token_endpoint_auth_method?: string;
	tenant_id?: string;
}

export interface UpdateApplicationRequest {
	name?: string;
	description?: string;
	redirect_uris?: string[];
	post_logout_uris?: string[];
	scope_ids?: string[];
	audience_ids?: string[];
	skip_authorization?: boolean;
}

export interface CreateScopeRequest {
	name: string;
	description?: string;
	is_default?: boolean;
}

export interface UpdateScopeRequest {
	name?: string;
	description?: string;
	is_default?: boolean;
}

export interface CreateAudienceRequest {
	identifier: string;
	name: string;
	description?: string;
	scope_ids?: string[];
}

export interface UpdateAudienceRequest {
	identifier?: string;
	name?: string;
	description?: string;
	scope_ids?: string[];
}

export interface CreateUserRequest {
	username: string;
	email: string;
	password: string;
	is_active?: boolean;
	is_admin?: boolean;
	role_ids?: string[];
}

export interface UpdateUserRequest {
	username?: string;
	email?: string;
	password?: string;
	is_active?: boolean;
	is_admin?: boolean;
	role_ids?: string[];
}

export interface AuditLogsResponse {
	logs: AuditLog[];
	total: number;
	page: number;
	limit: number;
}

export interface ApiError {
	error: string;
	message?: string;
}

// TrustSky Multi-tenancy support
export interface Tenant {
	id: string;
	name: string;
	type: 'operator' | 'authority' | 'emergency_service';
	status: 'active' | 'suspended' | 'revoked';
	email: string;
	certificate_subject?: string;
	description?: string;
	metadata?: Record<string, unknown>;
	created_at: string;
	updated_at: string;
}

export interface CreateTenantRequest {
	name: string;
	type: 'operator' | 'authority' | 'emergency_service';
	email: string;
	certificate_subject?: string;
	description?: string;
	metadata?: Record<string, unknown>;
}

export interface UpdateTenantRequest {
	name?: string;
	type?: 'operator' | 'authority' | 'emergency_service';
	email?: string;
	certificate_subject?: string;
	description?: string;
	metadata?: Record<string, unknown>;
}
