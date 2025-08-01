import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useMutation, useQueryClient, useQuery } from '@tanstack/react-query';
import { applicationsService } from '@/services/applications.service';
import { scopesService } from '@/services/scopes.service';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import { Loader2, Plus, X } from 'lucide-react';
import { toast } from 'sonner';

const applicationSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100),
  type: z.enum(['public', 'confidential']),
  redirectUris: z
    .array(z.url('Must be a valid URL')) // Fixed: use z.url() instead of z.string().url()
    .min(1, 'At least one redirect URI is required'),
  scopes: z.array(z.string()).default([]),
});

type ApplicationFormData = z.infer<typeof applicationSchema>;

interface CreateApplicationDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export const CreateApplicationDialog = (
  props: CreateApplicationDialogProps,
) => {
  const queryClient = useQueryClient();
  const [redirectUri, setRedirectUri] = useState('');

  const { data: scopes } = useQuery({
    queryKey: ['scopes', 'all'],
    queryFn: () => scopesService.getAll({ pageSize: 100 }),
  });

  const form = useForm({
    resolver: zodResolver(applicationSchema),
    defaultValues: {
      name: '',
      type: 'confidential',
      redirectUris: [],
      scopes: [],
    },
  });

  const createMutation = useMutation({
    mutationFn: applicationsService.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications'] });
      toast.success('Application created successfully');
      props.onOpenChange(false);
      form.reset();
    },
    onError: () => {
      toast.error('Failed to create application');
    },
  });

  const onSubmit = (data: ApplicationFormData) => {
    createMutation.mutate(data);
  };

  const addRedirectUri = () => {
    if (redirectUri && z.url().safeParse(redirectUri).success) {
      // Fixed: use z.url() instead of z.string().url()
      const currentUris = form.getValues('redirectUris');
      if (!currentUris.includes(redirectUri)) {
        form.setValue('redirectUris', [...currentUris, redirectUri]);
        setRedirectUri('');
      }
    } else {
      toast.error('Please enter a valid URL');
    }
  };

  const removeRedirectUri = (uri: string) => {
    const currentUris = form.getValues('redirectUris');
    form.setValue(
      'redirectUris',
      currentUris.filter((u) => u !== uri),
    );
  };

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle>Create Application</DialogTitle>
          <DialogDescription>
            Create a new OAuth2 client application
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input placeholder="My Application" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="type"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Type</FormLabel>
                  <Select
                    onValueChange={field.onChange}
                    defaultValue={field.value}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a type" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="confidential">Confidential</SelectItem>
                      <SelectItem value="public">Public</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    Confidential clients can securely store credentials, public
                    clients cannot
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="redirectUris"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Redirect URIs</FormLabel>
                  <div className="space-y-2">
                    <div className="flex gap-2">
                      <Input
                        placeholder="https://example.com/callback"
                        value={redirectUri}
                        onChange={(e) => setRedirectUri(e.target.value)}
                        onKeyPress={(e) =>
                          e.key === 'Enter' &&
                          (e.preventDefault(), addRedirectUri())
                        }
                      />
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        onClick={addRedirectUri}
                      >
                        <Plus className="h-4 w-4" />
                      </Button>
                    </div>
                    {field.value.length > 0 && (
                      <div className="space-y-1">
                        {field.value.map((uri) => (
                          <div key={uri} className="flex items-center gap-2">
                            <Badge
                              variant="secondary"
                              className="flex-1 justify-between"
                            >
                              <span className="truncate">{uri}</span>
                              <button
                                type="button"
                                onClick={() => removeRedirectUri(uri)}
                                className="ml-2 hover:text-red-500"
                              >
                                <X className="h-3 w-3" />
                              </button>
                            </Badge>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="scopes"
              render={() => (
                <FormItem>
                  <FormLabel>Scopes</FormLabel>
                  <div className="grid max-h-48 grid-cols-2 gap-3 overflow-y-auto rounded-md border p-3">
                    {scopes?.items.map((scope) => (
                      <FormField
                        key={scope.id}
                        control={form.control}
                        name="scopes"
                        render={({ field }) => {
                          return (
                            <FormItem
                              key={scope.id}
                              className="flex flex-row items-start space-y-0 space-x-3"
                            >
                              <FormControl>
                                <Checkbox
                                  checked={field.value?.includes(scope.name)}
                                  onCheckedChange={(
                                    checked: boolean | 'indeterminate',
                                  ) => {
                                    return checked
                                      ? field.onChange([
                                          ...(field.value || []),
                                          scope.name,
                                        ])
                                      : field.onChange(
                                          field.value?.filter(
                                            (value: string) =>
                                              value !== scope.name,
                                          ),
                                        );
                                  }}
                                />
                              </FormControl>
                              <FormLabel className="cursor-pointer text-sm font-normal">
                                {scope.name}
                              </FormLabel>
                            </FormItem>
                          );
                        }}
                      />
                    ))}
                  </div>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => props.onOpenChange(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Creating...
                  </>
                ) : (
                  'Create Application'
                )}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
};
