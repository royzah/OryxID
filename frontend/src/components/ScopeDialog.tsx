import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { useMutation } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { scopeService } from "../services/api";
import { useToast } from "./ui/use-toast";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Textarea } from "./ui/textarea";
import { Checkbox } from "./ui/checkbox";

interface ScopeDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  scope?: any;
  onSuccess: () => void;
}

interface ScopeForm {
  name: string;
  description: string;
  is_default: boolean;
}

export default function ScopeDialog({
  open,
  onOpenChange,
  scope,
  onSuccess,
}: ScopeDialogProps) {
  const { toast } = useToast();
  const isEdit = !!scope;

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    reset,
    formState: { errors },
  } = useForm<ScopeForm>({
    defaultValues: {
      name: "",
      description: "",
      is_default: false,
    },
  });

  useEffect(() => {
    if (scope) {
      reset({
        name: scope.name,
        description: scope.description || "",
        is_default: scope.is_default || false,
      });
    } else {
      reset();
    }
  }, [scope, reset]);

  const mutation = useMutation({
    mutationFn: async (data: ScopeForm) => {
      if (isEdit) {
        return await scopeService.update(scope.id, data);
      } else {
        return await scopeService.create(data);
      }
    },
    onSuccess: () => {
      toast({
        title: isEdit ? "Scope updated" : "Scope created",
        description: `The scope has been ${isEdit ? "updated" : "created"} successfully.`,
      });
      onSuccess();
    },
    onError: () => {
      toast({
        title: "Error",
        description: `Failed to ${isEdit ? "update" : "create"} the scope.`,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: ScopeForm) => {
    mutation.mutate(data);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <form onSubmit={handleSubmit(onSubmit)}>
          <DialogHeader>
            <DialogTitle>
              {isEdit ? "Edit Scope" : "Create New Scope"}
            </DialogTitle>
            <DialogDescription>
              {isEdit
                ? "Update the scope configuration."
                : "Define a new OAuth2 scope for your applications."}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                {...register("name", {
                  required: "Name is required",
                  pattern: {
                    value: /^[a-z0-9:_-]+$/,
                    message:
                      "Name must contain only lowercase letters, numbers, colons, underscores, and hyphens",
                  },
                })}
                placeholder="read:data"
                disabled={isEdit}
              />
              {errors.name && (
                <p className="text-sm text-red-600">{errors.name.message}</p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                {...register("description", {
                  required: "Description is required",
                })}
                placeholder="Allows read access to user data"
                rows={3}
              />
              {errors.description && (
                <p className="text-sm text-red-600">
                  {errors.description.message}
                </p>
              )}
            </div>

            <div className="flex items-center space-x-2">
              <Checkbox
                id="is_default"
                checked={watch("is_default")}
                onCheckedChange={(checked: boolean) =>
                  setValue("is_default", checked)
                }
              />
              <Label
                htmlFor="is_default"
                className="text-sm font-normal cursor-pointer"
              >
                Default scope (automatically included in all applications)
              </Label>
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {isEdit ? "Updating..." : "Creating..."}
                </>
              ) : (
                <>{isEdit ? "Update" : "Create"} Scope</>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
