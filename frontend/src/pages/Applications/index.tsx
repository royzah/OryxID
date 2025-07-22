import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Search, MoreVertical, Copy, Eye, EyeOff } from "lucide-react";
import { format } from "date-fns";
import api from "../../services/api";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "../../components/ui/dropdown-menu";
import { Badge } from "../../components/ui/badge";
import { useToast } from "../../components/ui/use-toast";
import ApplicationDialog from "../../components/ApplicationDialog";
import DeleteDialog from "../../components/DeleteDialog";

interface Application {
  id: string;
  name: string;
  description: string;
  client_id: string;
  client_type: string;
  grant_types: string[];
  scopes: Array<{ id: string; name: string }>;
  created_at: string;
  updated_at: string;
}

export default function Applications() {
  const [search, setSearch] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedApp, setSelectedApp] = useState<Application | null>(null);
  const [showSecrets, setShowSecrets] = useState<{ [key: string]: boolean }>(
    {}
  );

  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: applications, isLoading } = useQuery({
    queryKey: ["applications"],
    queryFn: async () => {
      const response = await api.get("/api/v1/applications");
      return response.data;
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/api/v1/applications/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["applications"] });
      toast({
        title: "Application deleted",
        description: "The application has been deleted successfully.",
      });
      setDeleteDialogOpen(false);
      setSelectedApp(null);
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete the application.",
        variant: "destructive",
      });
    },
  });

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast({
        title: "Copied",
        description: "Client ID copied to clipboard.",
      });
    } catch (err) {
      toast({
        title: "Error",
        description: "Failed to copy to clipboard.",
        variant: "destructive",
      });
    }
  };

  const filteredApplications = applications?.filter(
    (app: Application) =>
      app.name.toLowerCase().includes(search.toLowerCase()) ||
      app.client_id.toLowerCase().includes(search.toLowerCase())
  );

  const toggleSecretVisibility = (id: string) => {
    setShowSecrets((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
            <Input
              placeholder="Search applications..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10 w-80"
            />
          </div>
        </div>
        <Button
          onClick={() => {
            setSelectedApp(null);
            setDialogOpen(true);
          }}
        >
          <Plus className="mr-2 h-4 w-4" />
          New Application
        </Button>
      </div>

      <div className="rounded-lg border bg-white dark:bg-gray-800">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Client ID</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Grant Types</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="w-12"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8">
                  Loading...
                </TableCell>
              </TableRow>
            ) : filteredApplications?.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8">
                  No applications found
                </TableCell>
              </TableRow>
            ) : (
              filteredApplications?.map((app: Application) => (
                <TableRow key={app.id}>
                  <TableCell>
                    <div>
                      <div className="font-medium">{app.name}</div>
                      {app.description && (
                        <div className="text-sm text-gray-500">
                          {app.description}
                        </div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center space-x-2">
                      <code className="text-sm bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                        {showSecrets[app.id]
                          ? app.client_id
                          : "••••••••••••••••"}
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => toggleSecretVisibility(app.id)}
                      >
                        {showSecrets[app.id] ? (
                          <EyeOff className="h-4 w-4" />
                        ) : (
                          <Eye className="h-4 w-4" />
                        )}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(app.client_id)}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        app.client_type === "confidential"
                          ? "default"
                          : "secondary"
                      }
                    >
                      {app.client_type}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {app.grant_types.map((grant) => (
                        <Badge
                          key={grant}
                          variant="outline"
                          className="text-xs"
                        >
                          {grant}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    {format(new Date(app.created_at), "MMM d, yyyy")}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm">
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          onClick={() => {
                            setSelectedApp(app);
                            setDialogOpen(true);
                          }}
                        >
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="text-red-600"
                          onClick={() => {
                            setSelectedApp(app);
                            setDeleteDialogOpen(true);
                          }}
                        >
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <ApplicationDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        application={selectedApp}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ["applications"] });
          setDialogOpen(false);
          setSelectedApp(null);
        }}
      />

      <DeleteDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        onConfirm={() => selectedApp && deleteMutation.mutate(selectedApp.id)}
        title="Delete Application"
        description={`Are you sure you want to delete "${selectedApp?.name}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
