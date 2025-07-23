import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { audienceService, scopeService } from "../services/api";
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
import type { Audience } from "../types";

interface AudienceDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  audience?: Audience;
  onSuccess: () => void;
}

interface AudienceForm {
  identifier: string;
  name: string;
  description: string;
  scope_ids: string[];
}

export default function AudienceDialog({
  open,
  onOpenChange,
  audience,
  onSuccess,
}: AudienceDialogProps) {
  const { toast } = useToast();
  const isEdit = !!audience;

  const { data: scopes } = useQuery({
    queryKey: ["scopes"],
    queryFn: async () => {
      const response = await scopeService.list();
      return response.data;
    },
  });

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    reset,
    formState: { errors },
  } = useForm<AudienceForm>({
    defaultValues: {
      identifier: "",
      name: "",
      description: "",
      scope_ids: [],
    },
  });

  const selectedScopes = watch("scope_ids");

  useEffect(() => {
    if (audience) {
      reset({
        identifier: audience.identifier,
        name: audience.name || "",
        description: audience.description || "",
        scope_ids: audience.scopes?.map((s) => s.id) || [],
      });
    } else {
      reset();
    }
  }, [audience, reset]);

  const mutation = useMutation({
    mutationFn: async (data: AudienceForm) => {
      if (isEdit) {
        return await audienceService.update(audience.id, data);
      } else {
        return await audienceService.create(data);
      }
    },
    onSuccess: () => {
      toast({
        title: isEdit ? "Audience updated" : "Audience created",
        description: `The audience has been ${isEdit ? "updated" : "created"} successfully.`,
      });
      onSuccess();
    },
    onError: () => {
      toast({
        title: "Error",
        description: `Failed to ${isEdit ? "update" : "create"} the audience.`,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: AudienceForm) => {
    mutation.mutate(data);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <form onSubmit={handleSubmit(onSubmit)}>
          <DialogHeader>
            <DialogTitle>
              {isEdit ? "Edit Audience" : "Create New Audience"}
            </DialogTitle>
            <DialogDescription>
              {isEdit
                ? "Update the audience configuration."
                : "Configure a new API audience for token validation."}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="identifier">Identifier</Label>
              <Input
                id="identifier"
                {...register("identifier", {
                  required: "Identifier is required",
                  pattern: {
                    value: /^https?:\/\/.+/,
                    message: "Identifier must be a valid URL",
                  },
                })}
                placeholder="https://api.example.com"
                disabled={isEdit}
              />
              {errors.identifier && (
                <p className="text-sm text-red-600">
                  {errors.identifier.message}
                </p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                {...register("name", { required: "Name is required" })}
                placeholder="My API"
              />
              {errors.name && (
                <p className="text-sm text-red-600">{errors.name.message}</p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                {...register("description")}
                placeholder="API description..."
              />
            </div>

            <div className="grid gap-2">
              <Label>Available Scopes</Label>
              <div className="space-y-2 max-h-48 overflow-y-auto border rounded p-2">
                {scopes?.map((scope) => (
                  <div key={scope.id} className="flex items-center space-x-2">
                    <Checkbox
                      id={`scope-${scope.id}`}
                      checked={selectedScopes?.includes(scope.id)}
                      onCheckedChange={(checked) => {
                        if (checked) {
                          setValue("scope_ids", [
                            ...(selectedScopes || []),
                            scope.id,
                          ]);
                        } else {
                          setValue(
                            "scope_ids",
                            selectedScopes?.filter((id) => id !== scope.id) ||
                              [],
                          );
                        }
                      }}
                    />
                    <Label
                      htmlFor={`scope-${scope.id}`}
                      className="text-sm font-normal cursor-pointer"
                    >
                      {scope.name}
                      {scope.description && (
                        <span className="text-gray-500 ml-1">
                          - {scope.description}
                        </span>
                      )}
                    </Label>
                  </div>
                ))}
              </div>
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
                <>{isEdit ? "Update" : "Create"} Audience</>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
