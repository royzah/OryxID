export interface User {
  id: string;
  username: string;
  email: string;
  name: string;
  roles: string[];
  status: 'active' | 'inactive';
  createdAt: string;
  updatedAt: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
  remember?: boolean;
}

export interface AuthResponse {
  user: User;
  token: string;
  refreshToken: string;
  expiresIn: number;
}

export interface Application {
  id: string;
  name: string;
  clientId: string;
  clientSecret?: string;
  type: 'public' | 'confidential';
  redirectUris: string[];
  scopes: string[];
  createdAt: string;
  updatedAt: string;
}

export interface Scope {
  id: string;
  name: string;
  description: string;
  usageCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface AuditLog {
  id: string;
  userId: string;
  user: {
    name: string;
    email: string;
  };
  action: string;
  resource: string;
  ip: string;
  userAgent: string;
  metadata: Record<string, unknown>;
  timestamp: string;
}

export interface Statistics {
  totalApplications: number;
  activeUsers: number;
  totalScopes: number;
  activeTokens: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

export interface QueryParams {
  page?: number;
  pageSize?: number;
  search?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface CreateApplicationDto {
  name: string;
  type: 'public' | 'confidential';
  redirectUris: string[];
  scopes: string[];
}

export type UpdateApplicationDto = Partial<CreateApplicationDto>;

export interface CreateScopeDto {
  name: string;
  description: string;
}

export type UpdateScopeDto = Partial<CreateScopeDto>;

export interface CreateUserDto {
  username: string;
  email: string;
  name: string;
  password: string;
  roles: string[];
}

export interface UpdateUserDto
  extends Partial<Omit<CreateUserDto, 'password'>> {
  status?: 'active' | 'inactive';
}

export interface ChangePasswordDto {
  currentPassword: string;
  newPassword: string;
}
