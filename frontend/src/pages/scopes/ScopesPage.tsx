import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scopesService } from '@/services/scopes.service';
import { PageHeader } from '@/components/layout/PageHeader';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Plus, Search, Edit2, Trash2, Key } from 'lucide-react';
import { toast } from 'sonner';
import { useDebounce } from '@/hooks/useDebounce';
import { CreateScopeDialog } from '@/components/scopes/CreateScopeDialog';
import { EditScopeDialog } from '@/components/scopes/EditScopeDialog';
import type { Scope } from '@/types';

export const ScopesPage = () => {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [editingScope, setEditingScope] = useState<Scope | null>(null);
  const debouncedSearch = useDebounce(search, 300);

  const { data, isLoading } = useQuery({
    queryKey: ['scopes', { search: debouncedSearch }],
    queryFn: () =>
      scopesService.getAll({ search: debouncedSearch, pageSize: 50 }),
  });

  const deleteMutation = useMutation({
    mutationFn: scopesService.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scopes'] });
      toast.success('Scope deleted successfully');
    },
    onError: () => {
      toast.error('Failed to delete scope');
    },
  });

  const handleDelete = (scope: Scope) => {
    if (confirm(`Are you sure you want to delete "${scope.name}"?`)) {
      deleteMutation.mutate(scope.id);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scopes"
        description="Manage OAuth2 scopes and permissions"
        action={
          <Button onClick={() => setIsCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Create Scope
          </Button>
        }
      />

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-gray-400" />
        <Input
          placeholder="Search scopes..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-10"
        />
      </div>

      {/* Grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {isLoading ? (
          [...Array(6)].map((_, i) => (
            <Card key={i}>
              <CardHeader>
                <Skeleton className="h-5 w-32" />
                <Skeleton className="mt-2 h-4 w-full" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-4 w-20" />
              </CardContent>
            </Card>
          ))
        ) : (data?.items || []).length === 0 ? (
          <div className="col-span-full py-12 text-center">
            <Key className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-semibold text-gray-900">
              No scopes found
            </h3>
            <p className="mt-1 text-sm text-gray-500">
              Get started by creating a new scope.
            </p>
            <div className="mt-6">
              <Button onClick={() => setIsCreateOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                Create Scope
              </Button>
            </div>
          </div>
        ) : (
          data?.items.map((scope) => (
            <Card
              key={scope.id}
              className="group transition-shadow hover:shadow-md"
            >
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <Key className="h-4 w-4 text-purple-600" />
                      {scope.name}
                    </CardTitle>
                    <CardDescription className="text-sm">
                      {scope.description}
                    </CardDescription>
                  </div>
                  <div className="flex gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      onClick={() => setEditingScope(scope)}
                    >
                      <Edit2 className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      onClick={() => handleDelete(scope)}
                      disabled={deleteMutation.isPending}
                    >
                      <Trash2 className="h-4 w-4 text-red-500" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Badge variant="secondary">
                  {scope.usageCount} {scope.usageCount === 1 ? 'app' : 'apps'}
                </Badge>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      <CreateScopeDialog
        open={isCreateOpen}
        onOpenChange={() => setIsCreateOpen(!isCreateOpen)}
      />

      {editingScope && (
        <EditScopeDialog
          scope={editingScope}
          open={!!editingScope}
          onOpenChange={() => setEditingScope(null)}
        />
      )}
    </div>
  );
};
