export interface PaginatedRequest {
  page?: number;
  limit?: number;
  sort?: string;
  order?: "asc" | "desc";
}

export interface PaginatedResponse<T> {
  data: T[];
  meta: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}

// Branded types for IDs
type Brand<K, T> = K & { __brand: T };
export type UserId = Brand<string, "UserId">;
export type ApplicationId = Brand<string, "ApplicationId">;
export type ScopeId = Brand<string, "ScopeId">;
