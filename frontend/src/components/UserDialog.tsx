import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { useMutation } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { userService } from "../services/api";
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
import { Checkbox } from "./ui/checkbox";

interface UserDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user?: any;
  onSuccess: () => void;
}

interface UserForm {
  username: string;
  email: string;
  password?: string;
  is_active: boolean;
  is_admin: boolean;
}

export default function UserDialog({
  open,
  onOpenChange,
  user,
  onSuccess,
}: UserDialogProps) {
  const { toast } = useToast();
  const isEdit = !!user;

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    reset,
    formState: { errors },
  } = useForm<UserForm>({
    defaultValues: {
      username: "",
      email: "",
      password: "",
      is_active: true,
      is_admin: false,
    },
  });

  useEffect(() => {
    if (user) {
      reset({
        username: user.username,
        email: user.email,
        is_active: user.is_active,
        is_admin: user.is_admin,
      });
    } else {
      reset();
    }
  }, [user, reset]);

  const mutation = useMutation({
    mutationFn: async (data: UserForm) => {
      // Remove password if empty on edit
      if (isEdit && !data.password) {
        const { password, ...updateData } = data;
        return await userService.update(user.id, updateData);
      }

      if (isEdit) {
        return await userService.update(user.id, data);
      } else {
        return await userService.create(data);
      }
    },
    onSuccess: () => {
      toast({
        title: isEdit ? "User updated" : "User created",
        description: `The user has been ${isEdit ? "updated" : "created"} successfully.`,
      });
      onSuccess();
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description:
          error.response?.data?.error ||
          `Failed to ${isEdit ? "update" : "create"} the user.`,
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: UserForm) => {
    mutation.mutate(data);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <form onSubmit={handleSubmit(onSubmit)}>
          <DialogHeader>
            <DialogTitle>
              {isEdit ? "Edit User" : "Create New User"}
            </DialogTitle>
            <DialogDescription>
              {isEdit
                ? "Update the user account details."
                : "Create a new user account with access to the admin panel."}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                {...register("username", {
                  required: "Username is required",
                  minLength: {
                    value: 3,
                    message: "Username must be at least 3 characters",
                  },
                  pattern: {
                    value: /^[a-zA-Z0-9_-]+$/,
                    message:
                      "Username can only contain letters, numbers, underscores, and hyphens",
                  },
                })}
                placeholder="johndoe"
                disabled={isEdit}
              />
              {errors.username && (
                <p className="text-sm text-red-600">
                  {errors.username.message}
                </p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                {...register("email", {
                  required: "Email is required",
                  pattern: {
                    value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                    message: "Invalid email address",
                  },
                })}
                placeholder="john@example.com"
              />
              {errors.email && (
                <p className="text-sm text-red-600">{errors.email.message}</p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="password">
                Password {isEdit && "(leave empty to keep current)"}
              </Label>
              <Input
                id="password"
                type="password"
                {...register("password", {
                  required: isEdit ? false : "Password is required",
                  minLength: isEdit
                    ? undefined
                    : {
                        value: 8,
                        message: "Password must be at least 8 characters",
                      },
                })}
                placeholder="••••••••"
              />
              {errors.password && (
                <p className="text-sm text-red-600">
                  {errors.password.message}
                </p>
              )}
            </div>

            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="is_active"
                  checked={watch("is_active")}
                  onCheckedChange={(checked: boolean) =>
                    setValue("is_active", checked)
                  }
                />
                <Label
                  htmlFor="is_active"
                  className="text-sm font-normal cursor-pointer"
                >
                  Active (user can log in)
                </Label>
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="is_admin"
                  checked={watch("is_admin")}
                  onCheckedChange={(checked: boolean) =>
                    setValue("is_admin", checked)
                  }
                />
                <Label
                  htmlFor="is_admin"
                  className="text-sm font-normal cursor-pointer"
                >
                  Administrator (full access to admin panel)
                </Label>
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
                <>{isEdit ? "Update" : "Create"} User</>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
