import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { statsService } from '@/services/stats.service';
import { PageHeader } from '@/components/layout/PageHeader';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Calendar,
  Download,
  Filter,
  Search,
  User,
  Globe,
  Clock,
} from 'lucide-react';
import { format, subDays, startOfDay, endOfDay } from 'date-fns';
import { toast } from 'sonner';
import { useDebounce } from '@/hooks/useDebounce';

const actionTypes = [
  { value: 'all', label: 'All Actions' },
  { value: 'auth.login', label: 'Login' },
  { value: 'auth.logout', label: 'Logout' },
  { value: 'application.create', label: 'Create Application' },
  { value: 'application.update', label: 'Update Application' },
  { value: 'application.delete', label: 'Delete Application' },
  { value: 'user.create', label: 'Create User' },
  { value: 'user.update', label: 'Update User' },
  { value: 'user.delete', label: 'Delete User' },
  { value: 'scope.create', label: 'Create Scope' },
  { value: 'scope.update', label: 'Update Scope' },
  { value: 'scope.delete', label: 'Delete Scope' },
];

const dateRanges = [
  { value: 'today', label: 'Today' },
  { value: 'yesterday', label: 'Yesterday' },
  { value: '7days', label: 'Last 7 days' },
  { value: '30days', label: 'Last 30 days' },
  { value: 'custom', label: 'Custom range' },
];

export const AuditPage = () => {
  const [search, setSearch] = useState('');
  const [actionType, setActionType] = useState('all');
  const [dateRange, setDateRange] = useState('7days');
  const [expandedLogs, setExpandedLogs] = useState<Set<string>>(new Set());
  const debouncedSearch = useDebounce(search, 300);

  // Calculate date range
  const getDateRange = () => {
    const now = new Date();
    let yesterday: Date;

    switch (dateRange) {
      case 'today':
        return {
          startDate: startOfDay(now).toISOString(),
          endDate: endOfDay(now).toISOString(),
        };
      case 'yesterday':
        yesterday = subDays(now, 1);
        return {
          startDate: startOfDay(yesterday).toISOString(),
          endDate: endOfDay(yesterday).toISOString(),
        };
      case '7days':
        return {
          startDate: subDays(now, 7).toISOString(),
          endDate: now.toISOString(),
        };
      case '30days':
        return {
          startDate: subDays(now, 30).toISOString(),
          endDate: now.toISOString(),
        };
      default:
        return {};
    }
  };

  const { data, isLoading } = useQuery({
    queryKey: [
      'audit-logs',
      {
        search: debouncedSearch,
        action: actionType === 'all' ? undefined : actionType,
        ...getDateRange(),
      },
    ],
    queryFn: () =>
      statsService.getAuditLogs({
        search: debouncedSearch || undefined,
        action: actionType === 'all' ? undefined : actionType,
        ...getDateRange(),
        pageSize: 50,
      }),
  });

  const handleExport = async () => {
    try {
      const blob = await statsService.exportAuditLogs({
        search: debouncedSearch || undefined,
        action: actionType === 'all' ? undefined : actionType,
        ...getDateRange(),
      });

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit-logs-${format(new Date(), 'yyyy-MM-dd')}.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toast.success('Audit logs exported successfully');
    } catch {
      toast.error('Failed to export audit logs');
    }
  };

  const toggleExpanded = (logId: string) => {
    const newExpanded = new Set(expandedLogs);
    if (newExpanded.has(logId)) {
      newExpanded.delete(logId);
    } else {
      newExpanded.add(logId);
    }
    setExpandedLogs(newExpanded);
  };

  const getActionColor = (action: string) => {
    if (action.includes('create')) return 'text-green-600 bg-green-50';
    if (action.includes('update')) return 'text-blue-600 bg-blue-50';
    if (action.includes('delete')) return 'text-red-600 bg-red-50';
    if (action.includes('login')) return 'text-purple-600 bg-purple-50';
    return 'text-gray-600 bg-gray-50';
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Logs"
        description="Track all system activities and changes"
        action={
          <Button onClick={handleExport} variant="outline">
            <Download className="mr-2 h-4 w-4" />
            Export CSV
          </Button>
        }
      />

      {/* Filters */}
      <Card>
        <CardContent className="p-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <Label className="sr-only">Search</Label>
              <div className="relative">
                <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-gray-400" />
                <Input
                  placeholder="Search by user or resource..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>

            <div>
              <Label className="sr-only">Action Type</Label>
              <Select value={actionType} onValueChange={setActionType}>
                <SelectTrigger>
                  <Filter className="mr-2 h-4 w-4" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {actionTypes.map((type) => (
                    <SelectItem key={type.value} value={type.value}>
                      {type.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="sr-only">Date Range</Label>
              <Select value={dateRange} onValueChange={setDateRange}>
                <SelectTrigger>
                  <Calendar className="mr-2 h-4 w-4" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {dateRanges.map((range) => (
                    <SelectItem key={range.value} value={range.value}>
                      {range.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Timeline */}
      <div className="space-y-4">
        {isLoading ? (
          [...Array(10)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-4">
                <div className="flex items-start gap-4">
                  <Skeleton className="h-10 w-10 rounded-full" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-3/4" />
                    <Skeleton className="h-3 w-1/2" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        ) : (data?.items || []).length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <p className="text-gray-500">
                No audit logs found for the selected filters
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute top-0 bottom-0 left-6 w-0.5 bg-gray-200" />

            {data?.items.map((log) => (
              <div key={log.id} className="relative flex gap-4 pb-8 last:pb-0">
                {/* Timeline dot */}
                <div className="relative z-10 flex h-12 w-12 items-center justify-center rounded-full border-2 border-gray-200 bg-white">
                  <User className="h-5 w-5 text-gray-600" />
                </div>

                {/* Content */}
                <Card
                  className="flex-1 cursor-pointer transition-shadow hover:shadow-md"
                  onClick={() => toggleExpanded(log.id)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 space-y-2">
                        <div className="flex flex-wrap items-center gap-3">
                          <span className="font-medium">{log.user.name}</span>
                          <Badge
                            variant="secondary"
                            className={getActionColor(log.action)}
                          >
                            {log.action}
                          </Badge>
                          <span className="text-sm text-gray-500">
                            {log.resource}
                          </span>
                        </div>

                        <div className="flex items-center gap-4 text-xs text-gray-500">
                          <div className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {format(new Date(log.timestamp), 'PPp')}
                          </div>
                          <div className="flex items-center gap-1">
                            <Globe className="h-3 w-3" />
                            {log.ip}
                          </div>
                        </div>

                        {expandedLogs.has(log.id) && log.metadata && (
                          <div className="mt-4 border-t pt-4">
                            <h4 className="mb-2 text-sm font-medium">
                              Additional Details
                            </h4>
                            <pre className="overflow-x-auto rounded bg-gray-50 p-3 text-xs">
                              {JSON.stringify(log.metadata, null, 2)}
                            </pre>
                            <p className="mt-2 text-xs text-gray-500">
                              User Agent: {log.userAgent}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
