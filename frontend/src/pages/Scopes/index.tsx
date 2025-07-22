import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, MoreVertical } from "lucide-react";
import { scopeService } from "../../services/api";
import { Button } from "../../components/ui/button";
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
import ScopeDialog from "../../components/ScopeDialog";
import DeleteDialog from "../../components/DeleteDialog";

interface Scope {
  id: string;
  name: string;
  description: string;
  is_default: boolean;
  created_at: string;
}

export default function Scopes() {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedScope, setSelectedScope] = useState<Scope | null>(null);

  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: scopes, isLoading } = useQuery({
    queryKey: ["scopes"],
    queryFn: async () => {
      const response = await scopeService.list();
      return response.data;
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await scopeService.delete(id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scopes"] });
      toast({
        title: "Scope deleted",
        description: "The scope has been deleted successfully.",
      });
      setDeleteDialogOpen(false);
      setSelectedScope(null);
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete the scope.",
        variant: "destructive",
      });
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scopes</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Manage OAuth2 scopes and permissions
          </p>
        </div>
        <Button
          onClick={() => {
            setSelectedScope(null);
            setDialogOpen(true);
          }}
        >
          <Plus className="mr-2 h-4 w-4" />
          New Scope
        </Button>
      </div>

      <div className="rounded-lg border bg-white dark:bg-gray-800">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Description</TableHead>
              <TableHead>Type</TableHead>
              <TableHead className="w-12"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center py-8">
                  Loading...
                </TableCell>
              </TableRow>
            ) : scopes?.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center py-8">
                  No scopes found
                </TableCell>
              </TableRow>
            ) : (
              scopes?.map((scope: Scope) => (
                <TableRow key={scope.id}>
                  <TableCell>
                    <code className="text-sm bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                      {scope.name}
                    </code>
                  </TableCell>
                  <TableCell>{scope.description}</TableCell>
                  <TableCell>
                    {scope.is_default ? (
                      <Badge variant="default">Default</Badge>
                    ) : (
                      <Badge variant="outline">Custom</Badge>
                    )}
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
                            setSelectedScope(scope);
                            setDialogOpen(true);
                          }}
                        >
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="text-red-600"
                          onClick={() => {
                            setSelectedScope(scope);
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

      <ScopeDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        scope={selectedScope}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ["scopes"] });
          setDialogOpen(false);
          setSelectedScope(null);
        }}
      />

      <DeleteDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        onConfirm={() =>
          selectedScope && deleteMutation.mutate(selectedScope.id)
        }
        title="Delete Scope"
        description={`Are you sure you want to delete "${selectedScope?.name}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
