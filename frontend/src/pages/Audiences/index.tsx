import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, MoreVertical, Shield } from "lucide-react";
import { audienceService } from "../../services/api";
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
import AudienceDialog from "../../components/AudienceDialog";
import DeleteDialog from "../../components/DeleteDialog";

interface Audience {
  id: string;
  identifier: string;
  name: string;
  description: string;
  scopes: Array<{ id: string; name: string }>;
  created_at: string;
}

export default function Audiences() {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedAudience, setSelectedAudience] = useState<Audience | null>(
    null
  );

  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: audiences, isLoading } = useQuery({
    queryKey: ["audiences"],
    queryFn: async () => {
      const response = await audienceService.list();
      return response.data;
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await audienceService.delete(id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["audiences"] });
      toast({
        title: "Audience deleted",
        description: "The audience has been deleted successfully.",
      });
      setDeleteDialogOpen(false);
      setSelectedAudience(null);
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete the audience.",
        variant: "destructive",
      });
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Audiences</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Configure API audiences for token validation
          </p>
        </div>
        <Button
          onClick={() => {
            setSelectedAudience(null);
            setDialogOpen(true);
          }}
        >
          <Plus className="mr-2 h-4 w-4" />
          New Audience
        </Button>
      </div>

      <div className="rounded-lg border bg-white dark:bg-gray-800">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Identifier</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Description</TableHead>
              <TableHead>Scopes</TableHead>
              <TableHead className="w-12"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8">
                  Loading...
                </TableCell>
              </TableRow>
            ) : audiences?.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8">
                  No audiences found
                </TableCell>
              </TableRow>
            ) : (
              audiences?.map((audience: Audience) => (
                <TableRow key={audience.id}>
                  <TableCell>
                    <div className="flex items-center space-x-2">
                      <Shield className="h-4 w-4 text-gray-400" />
                      <code className="text-sm bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                        {audience.identifier}
                      </code>
                    </div>
                  </TableCell>
                  <TableCell className="font-medium">{audience.name}</TableCell>
                  <TableCell className="text-sm text-gray-600 dark:text-gray-400">
                    {audience.description}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {audience.scopes.slice(0, 3).map((scope) => (
                        <Badge
                          key={scope.id}
                          variant="outline"
                          className="text-xs"
                        >
                          {scope.name}
                        </Badge>
                      ))}
                      {audience.scopes.length > 3 && (
                        <Badge variant="outline" className="text-xs">
                          +{audience.scopes.length - 3} more
                        </Badge>
                      )}
                    </div>
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
                            setSelectedAudience(audience);
                            setDialogOpen(true);
                          }}
                        >
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="text-red-600"
                          onClick={() => {
                            setSelectedAudience(audience);
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

      <AudienceDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        audience={selectedAudience}
        onSuccess={() => {
          queryClient.invalidateQueries({ queryKey: ["audiences"] });
          setDialogOpen(false);
          setSelectedAudience(null);
        }}
      />

      <DeleteDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        onConfirm={() =>
          selectedAudience && deleteMutation.mutate(selectedAudience.id)
        }
        title="Delete Audience"
        description={`Are you sure you want to delete "${selectedAudience?.name}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
