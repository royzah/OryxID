import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import {
  applicationService,
  scopeService,
  audienceService,
} from "../services/api";
import { useToast } from "./ui/use-toast";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog.tsx";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Textarea } from "./ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";
import { Checkbox } from "./ui/checkbox";

interface ApplicationDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  application?: any;
  onSuccess: () => void;
}

interface ApplicationForm {
  name: string;
  description: string;
  client_type: string;
  grant_types: string[];
  redirect_uris: string;
  post_logout_uris: string;
  scope_ids: string[];
  audience_ids: string[];
  skip_authorization: boolean;
}

const grantTypes = [
  { value: "authorization_code", label: "Authorization Code" },
  { value: "client_credentials", label: "Client Credentials" },
  { value: "refresh_token", label: "Refresh Token" },
  { value: "implicit", label: "Implicit" },
  { value: "password", label: "Password" },
];

export default function ApplicationDialog({
  open,
  onOpenChange,
  application,
  onSuccess,
}: ApplicationDialogProps) {
  const { toast } = useToast();
  const isEdit = !!application;

  const { data: scopes } = useQuery({
    queryKey: ["scopes"],
    queryFn: async () => {
      const response = await scopeService.list();
      return response.data;
    },
  });

  const { data: audiences } = useQuery({
    queryKey: ["audiences"],
    queryFn: async () => {
      const response = await audienceService.list();
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
  } = useForm<ApplicationForm>({
    defaultValues: {
      name: "",
      description: "",
      client_type: "confidential",
      grant_types: ["authorization_code"],
      redirect_uris: "",
      post_logout_uris: "",
      scope_ids: [],
      audience_ids: [],
      skip_authorization: false,
    },
  });

  const selectedGrantTypes = watch("grant_types");
  const selectedScopes = watch("scope_ids");
  const selectedAudiences = watch("audience_ids");

  useEffect(() => {
    if (application) {
      reset({
        name: application.name,
        description: application.description || "",
        client_type: application.client_type,
        grant_types: application.grant_types,
        redirect_uris: application.redirect_uris?.join("\n") || "",
        post_logout_uris: application.post_logout_uris?.join("\n") || "",
        scope_ids: application.scopes?.map((s: any) => s.id) || [],
        audience_ids: application.audiences?.map((a: any) => a.id) || [],
        skip_authorization: application.skip_authorization,
      });
    } else {
      reset();
    }
  }, [application, reset]);

  const mutation = useMutation({
    mutationFn: async (data: ApplicationForm) => {
      const payload = {
        ...data,
        redirect_uris: data.redirect_uris.split("\n").filter(Boolean),
        post_logout_uris: data.post_logout_uris.split("\n").filter(Boolean),
        response_types: data.grant_types.includes("authorization_code")
          ? ["code"]
          : [],
      };

      if (isEdit) {
        return await applicationService.update(application.id, payload);
      } else {
        return await applicationService.create(payload);
      }
    },
    onSuccess: (response) => {
      if (!isEdit && response.data.client_secret) {
        // Show client secret for new applications
        toast({
          title: "Application created",
          description: (
            <div className="space-y-2">
              <p>Your application has been created successfully.</p>
              <div className="bg-gray-100 dark:bg-gray-800 p-2 rounded">
                <p className="text-xs font-semibold">
                  Client Secret (save this now!):
                </p>
                <code className="text-xs break-all">
                  {response.data.client_secret}
                </code>
              </div>
            </div>
          ),
          duration: 10000,
        });
      } else {
        toast({
          title: isEdit ? "Application updated" : "Application created",
          description: `The application has been ${isEdit ? "updated" : "created"} successfully.`,
        });
      }
      onSuccess();
    },
    onError: () => {
      toast({
        title: "Error",
        description: `Failed to ${isEdit ? "update" : "create"} the application.`,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: ApplicationForm) => {
    mutation.mutate(data);
  };

  const toggleGrantType = (grantType: string) => {
    const current = selectedGrantTypes || [];
    if (current.includes(grantType)) {
      setValue(
        "grant_types",
        current.filter((gt) => gt !== grantType),
      );
    } else {
      setValue("grant_types", [...current, grantType]);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <form onSubmit={handleSubmit(onSubmit)}>
          <DialogHeader>
            <DialogTitle>
              {isEdit ? "Edit Application" : "Create New Application"}
            </DialogTitle>
            <DialogDescription>
              {isEdit
                ? "Update the application configuration."
                : "Register a new OAuth2 client application."}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                {...register("name", { required: "Name is required" })}
                placeholder="My Application"
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
                placeholder="Application description..."
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="client_type">Client Type</Label>
              <Select
                value={watch("client_type")}
                onValueChange={(value) => setValue("client_type", value)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="confidential">
                    Confidential (can keep secrets)
                  </SelectItem>
                  <SelectItem value="public">
                    Public (mobile/SPA apps)
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid gap-2">
              <Label>Grant Types</Label>
              <div className="space-y-2">
                {grantTypes.map((grant) => (
                  <div
                    key={grant.value}
                    className="flex items-center space-x-2"
                  >
                    <Checkbox
                      id={grant.value}
                      checked={selectedGrantTypes?.includes(grant.value)}
                      onCheckedChange={() => toggleGrantType(grant.value)}
                    />
                    <Label
                      htmlFor={grant.value}
                      className="text-sm font-normal cursor-pointer"
                    >
                      {grant.label}
                    </Label>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="redirect_uris">
                Redirect URIs (one per line)
              </Label>
              <Textarea
                id="redirect_uris"
                {...register("redirect_uris", {
                  required: "At least one redirect URI is required",
                })}
                placeholder="https://app.example.com/callback"
                rows={3}
              />
              {errors.redirect_uris && (
                <p className="text-sm text-red-600">
                  {errors.redirect_uris.message}
                </p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="post_logout_uris">
                Post Logout URIs (one per line)
              </Label>
              <Textarea
                id="post_logout_uris"
                {...register("post_logout_uris")}
                placeholder="https://app.example.com/logout"
                rows={2}
              />
            </div>

            <div className="grid gap-2">
              <Label>Scopes</Label>
              <div className="space-y-2 max-h-32 overflow-y-auto border rounded p-2">
                {scopes?.map((scope: any) => (
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

            <div className="grid gap-2">
              <Label>Audiences</Label>
              <div className="space-y-2 max-h-32 overflow-y-auto border rounded p-2">
                {audiences?.map((audience: any) => (
                  <div
                    key={audience.id}
                    className="flex items-center space-x-2"
                  >
                    <Checkbox
                      id={`audience-${audience.id}`}
                      checked={selectedAudiences?.includes(audience.id)}
                      onCheckedChange={(checked) => {
                        if (checked) {
                          setValue("audience_ids", [
                            ...(selectedAudiences || []),
                            audience.id,
                          ]);
                        } else {
                          setValue(
                            "audience_ids",
                            selectedAudiences?.filter(
                              (id) => id !== audience.id,
                            ) || [],
                          );
                        }
                      }}
                    />
                    <Label
                      htmlFor={`audience-${audience.id}`}
                      className="text-sm font-normal cursor-pointer"
                    >
                      {audience.identifier}
                      {audience.name && (
                        <span className="text-gray-500 ml-1">
                          - {audience.name}
                        </span>
                      )}
                    </Label>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <Checkbox
                id="skip_authorization"
                {...register("skip_authorization")}
              />
              <Label
                htmlFor="skip_authorization"
                className="text-sm font-normal cursor-pointer"
              >
                Skip authorization (trusted first-party app)
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
                <>{isEdit ? "Update" : "Create"} Application</>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
