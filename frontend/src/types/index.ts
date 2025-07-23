export interface User {
  id: string;
  username: string;
  email: string;
  is_active: boolean;
  is_admin: boolean;
  roles?: string[];
}

export interface Scope {
  id: string;
  name: string;
  description?: string;
  is_default?: boolean;
}

export interface Audience {
  id: string;
  identifier: string;
  name: string;
  description?: string;
  scopes?: Scope[];
}

export interface Application {
  id: string;
  name: string;
  description?: string;
  client_id: string;
  client_type: string;
  grant_types: string[];
  redirect_uris?: string[];
  post_logout_uris?: string[];
  scopes?: Scope[];
  audiences?: Audience[];
  skip_authorization?: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuditLog {
  id: string;
  user?: { id: string; username: string };
  application?: { id: string; name: string };
  action: string;
  resource: string;
  resource_id: string;
  ip_address: string;
  user_agent: string;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface AuditLogResponse {
  logs: AuditLog[];
  total: number;
}

export interface ApiResponse<T = unknown> {
  data: T;
  client_secret?: string;
}

export interface ApiError {
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
}
