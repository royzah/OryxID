import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { scopesService } from '@/services/scopes.service';
import type { Scope } from '@/types';
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
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';

const scopeSchema = z.object({
  description: z.string().min(1, 'Description is required').max(200),
});

type ScopeFormData = z.infer<typeof scopeSchema>;

interface EditScopeDialogProps {
  scope: Scope;
  open: boolean;
  onOpenChange: () => void;
}

export const EditScopeDialog = ({
  scope,
  open,
  onOpenChange,
}: EditScopeDialogProps) => {
  const queryClient = useQueryClient();

  const form = useForm<ScopeFormData>({
    resolver: zodResolver(scopeSchema),
    defaultValues: {
      description: scope.description,
    },
  });

  const updateMutation = useMutation({
    mutationFn: (data: ScopeFormData) => scopesService.update(scope.id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scopes'] });
      toast.success('Scope updated successfully');
      onOpenChange();
    },
    onError: () => {
      toast.error('Failed to update scope');
    },
  });

  const onSubmit = (data: ScopeFormData) => {
    updateMutation.mutate(data);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit Scope</DialogTitle>
          <DialogDescription>Update the scope description</DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="description"
              render={() => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input value={scope.name} disabled />
                  </FormControl>
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Textarea {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange()}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateMutation.isPending}>
                {updateMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Updating...
                  </>
                ) : (
                  'Update Scope'
                )}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
};
