import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { applicationsService } from '@/services/applications.service';
import { scopesService } from '@/services/scopes.service';
import type { UpdateApplicationDto } from '@/types';
import { PageHeader } from '@/components/layout/PageHeader';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Skeleton } from '@/components/ui/skeleton';
import {
  ArrowLeft,
  Copy,
  RefreshCw,
  Trash2,
  Plus,
  X,
  Shield,
  Key,
  Link,
  Settings,
} from 'lucide-react';
import { toast } from 'sonner';
import { format } from 'date-fns';

export const ApplicationDetailPage = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [newRedirectUri, setNewRedirectUri] = useState('');
  const [showSecret, setShowSecret] = useState(false);

  const { data: application, isLoading } = useQuery({
    queryKey: ['applications', id],
    queryFn: () => applicationsService.getById(id!),
    enabled: !!id,
  });

  const { data: scopes } = useQuery({
    queryKey: ['scopes', 'all'],
    queryFn: () => scopesService.getAll({ pageSize: 100 }),
  });

  const updateMutation = useMutation({
    mutationFn: (data: UpdateApplicationDto) =>
      applicationsService.update(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications', id] });
      toast.success('Application updated successfully');
    },
    onError: () => {
      toast.error('Failed to update application');
    },
  });

  const regenerateSecretMutation = useMutation({
    mutationFn: () => applicationsService.regenerateSecret(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications', id] });
      toast.success('Client secret regenerated successfully');
      setShowSecret(true);
    },
    onError: () => {
      toast.error('Failed to regenerate client secret');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => applicationsService.delete(id!),
    onSuccess: () => {
      toast.success('Application deleted successfully');
      navigate('/applications');
    },
    onError: () => {
      toast.error('Failed to delete application');
    },
  });

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  const addRedirectUri = () => {
    if (newRedirectUri && application) {
      const updatedUris = [...application.redirectUris, newRedirectUri];
      updateMutation.mutate({ redirectUris: updatedUris });
      setNewRedirectUri('');
    }
  };

  const removeRedirectUri = (uri: string) => {
    if (application) {
      const updatedUris = application.redirectUris.filter((u) => u !== uri);
      updateMutation.mutate({ redirectUris: updatedUris });
    }
  };

  const toggleScope = (scopeName: string) => {
    if (application) {
      const updatedScopes = application.scopes.includes(scopeName)
        ? application.scopes.filter((s) => s !== scopeName)
        : [...application.scopes, scopeName];
      updateMutation.mutate({ scopes: updatedScopes });
    }
  };

  const handleDelete = () => {
    if (
      confirm(
        `Are you sure you want to delete "${application?.name}"? This action cannot be undone.`,
      )
    ) {
      deleteMutation.mutate();
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  if (!application) {
    return <div>Application not found</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => navigate('/applications')}
        >
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <PageHeader
          title={application.name}
          description={`Client ID: ${application.clientId}`}
        />
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">
            <Shield className="mr-2 h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="scopes">
            <Key className="mr-2 h-4 w-4" />
            Scopes
          </TabsTrigger>
          <TabsTrigger value="redirects">
            <Link className="mr-2 h-4 w-4" />
            Redirect URIs
          </TabsTrigger>
          <TabsTrigger value="settings">
            <Settings className="mr-2 h-4 w-4" />
            Settings
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Client Details</CardTitle>
              <CardDescription>
                OAuth2 client configuration and credentials
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <Label>Client ID</Label>
                  <div className="mt-1 flex items-center gap-2">
                    <Input value={application.clientId} readOnly />
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={() =>
                        copyToClipboard(application.clientId, 'Client ID')
                      }
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {application.type === 'confidential' && (
                  <div>
                    <Label>Client Secret</Label>
                    <div className="mt-1 flex items-center gap-2">
                      <Input
                        type={showSecret ? 'text' : 'password'}
                        value={application.clientSecret || '••••••••••••••••'}
                        readOnly
                      />
                      {application.clientSecret && (
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={() =>
                            copyToClipboard(
                              application.clientSecret!,
                              'Client Secret',
                            )
                          }
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      )}
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={() => regenerateSecretMutation.mutate()}
                        disabled={regenerateSecretMutation.isPending}
                      >
                        <RefreshCw className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                )}
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <Label>Type</Label>
                  <div className="mt-1">
                    <Badge
                      variant={
                        application.type === 'confidential'
                          ? 'default'
                          : 'secondary'
                      }
                    >
                      {application.type}
                    </Badge>
                  </div>
                </div>

                <div>
                  <Label>Created</Label>
                  <p className="mt-1 text-sm text-gray-600">
                    {format(new Date(application.createdAt), 'PPP')}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scopes" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Assigned Scopes</CardTitle>
              <CardDescription>
                Select the scopes this application can request
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                {scopes?.items.map((scope) => (
                  <div key={scope.id} className="flex items-start space-x-3">
                    <Checkbox
                      checked={application.scopes.includes(scope.name)}
                      onCheckedChange={() => toggleScope(scope.name)}
                      disabled={updateMutation.isPending}
                    />
                    <div className="space-y-1">
                      <Label className="cursor-pointer text-sm font-medium">
                        {scope.name}
                      </Label>
                      <p className="text-sm text-gray-500">
                        {scope.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="redirects" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Redirect URIs</CardTitle>
              <CardDescription>
                Allowed redirect URIs for this application
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Input
                  placeholder="https://example.com/callback"
                  value={newRedirectUri}
                  onChange={(e) => setNewRedirectUri(e.target.value)}
                  onKeyPress={(e) =>
                    e.key === 'Enter' && (e.preventDefault(), addRedirectUri())
                  }
                />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={addRedirectUri}
                  disabled={updateMutation.isPending}
                >
                  <Plus className="h-4 w-4" />
                </Button>
              </div>

              <div className="space-y-2">
                {application.redirectUris.map((uri) => (
                  <div
                    key={uri}
                    className="flex items-center justify-between rounded-lg border p-3"
                  >
                    <code className="text-sm">{uri}</code>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => removeRedirectUri(uri)}
                      disabled={updateMutation.isPending}
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Token Settings</CardTitle>
              <CardDescription>
                Configure token lifetimes and other settings
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* Add token settings here */}
              <p className="text-sm text-gray-500">
                Token settings coming soon...
              </p>
            </CardContent>
          </Card>

          <Card className="border-red-200">
            <CardHeader>
              <CardTitle className="text-red-600">Danger Zone</CardTitle>
              <CardDescription>
                Irreversible and destructive actions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button
                variant="destructive"
                onClick={handleDelete}
                disabled={deleteMutation.isPending}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete Application
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};
