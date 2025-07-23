import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileText, User, Package, Shield, Clock } from "lucide-react";
import { auditService } from "../../services/api";
import { format } from "date-fns";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../../components/ui/table";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";

const actionColors: Record<string, string> = {
  "user.login": "bg-green-100 text-green-800",
  "user.logout": "bg-gray-100 text-gray-800",
  "application.created": "bg-blue-100 text-blue-800",
  "application.updated": "bg-yellow-100 text-yellow-800",
  "application.deleted": "bg-red-100 text-red-800",
  "token.issued": "bg-purple-100 text-purple-800",
  "token.revoked": "bg-orange-100 text-orange-800",
};

const resourceIcons: Record<string, React.ElementType> = {
  user: User,
  application: Package,
  audience: Shield,
  default: FileText,
};

export default function AuditLogs() {
  const [page, setPage] = useState(1);
  const limit = 50;

  const { data, isLoading } = useQuery({
    queryKey: ["audit-logs", page],
    queryFn: async () => {
      const response = await auditService.list({ page, limit });
      return response.data;
    },
  });

  const logs = data?.logs || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / limit);

  const getActionColor = (action: string) => {
    return actionColors[action] || "bg-gray-100 text-gray-800";
  };

  const getResourceIcon = (resource: string) => {
    const Icon = resourceIcons[resource] || resourceIcons.default;
    return <Icon className="h-4 w-4" />;
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Audit Logs</h1>
        <p className="text-gray-600 dark:text-gray-400">
          Track all system activities and changes
        </p>
      </div>

      <div className="rounded-lg border bg-white dark:bg-gray-800">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Resource</TableHead>
              <TableHead>IP Address</TableHead>
              <TableHead>Details</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8">
                  Loading...
                </TableCell>
              </TableRow>
            ) : logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8">
                  No audit logs found
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => (
                <TableRow key={log.id}>
                  <TableCell>
                    <div className="flex items-center space-x-1 text-sm">
                      <Clock className="h-3 w-3 text-gray-400" />
                      <span>
                        {format(new Date(log.created_at), "MMM d, HH:mm")}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    {log.user ? (
                      <div className="flex items-center space-x-2">
                        <User className="h-4 w-4 text-gray-400" />
                        <span className="text-sm">{log.user.username}</span>
                      </div>
                    ) : log.application ? (
                      <div className="flex items-center space-x-2">
                        <Package className="h-4 w-4 text-gray-400" />
                        <span className="text-sm">{log.application.name}</span>
                      </div>
                    ) : (
                      <span className="text-sm text-gray-500">System</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={`text-xs ${getActionColor(log.action)}`}
                    >
                      {log.action}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center space-x-2">
                      {getResourceIcon(log.resource)}
                      <span className="text-sm">{log.resource}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                      {log.ip_address}
                    </code>
                  </TableCell>
                  <TableCell>
                    {log.resource_id && (
                      <span className="text-xs text-gray-500">
                        ID: {log.resource_id.slice(0, 8)}...
                      </span>
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-6 py-4 border-t">
            <div className="text-sm text-gray-600 dark:text-gray-400">
              Showing {(page - 1) * limit + 1} to{" "}
              {Math.min(page * limit, total)} of {total} entries
            </div>
            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(page - 1)}
                disabled={page === 1}
              >
                Previous
              </Button>
              <span className="text-sm">
                Page {page} of {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(page + 1)}
                disabled={page === totalPages}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
