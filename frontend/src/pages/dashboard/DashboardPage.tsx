import { useQuery } from '@tanstack/react-query';
import { statsService } from '@/services/stats.service';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Shield, Key, Users, Zap } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

const StatCard = ({
  title,
  value,
  icon: Icon,
  isLoading,
}: {
  title: string;
  value: number;
  icon: LucideIcon;
  isLoading: boolean;
}) => (
  <Card>
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium">{title}</CardTitle>
      <Icon className="h-4 w-4 text-purple-600" />
    </CardHeader>
    <CardContent>
      {isLoading ? (
        <Skeleton className="h-8 w-16" />
      ) : (
        <div className="text-2xl font-bold">{value.toLocaleString()}</div>
      )}
    </CardContent>
  </Card>
);

export const DashboardPage = () => {
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['statistics'],
    queryFn: statsService.getStatistics,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: auditLogs, isLoading: logsLoading } = useQuery({
    queryKey: ['audit-logs', 'recent'],
    queryFn: () => statsService.getAuditLogs({ pageSize: 10 }),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="Overview of your OAuth2 infrastructure"
      />

      {/* Statistics Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Applications"
          value={stats?.totalApplications || 0}
          icon={Shield}
          isLoading={statsLoading}
        />
        <StatCard
          title="Active Users"
          value={stats?.activeUsers || 0}
          icon={Users}
          isLoading={statsLoading}
        />
        <StatCard
          title="Total Scopes"
          value={stats?.totalScopes || 0}
          icon={Key}
          isLoading={statsLoading}
        />
        <StatCard
          title="Active Tokens"
          value={stats?.activeTokens || 0}
          icon={Zap}
          isLoading={statsLoading}
        />
      </div>

      {/* Recent Activity */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Activity</CardTitle>
        </CardHeader>
        <CardContent>
          {logsLoading ? (
            <div className="space-y-4">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-center space-x-4">
                  <Skeleton className="h-10 w-10 rounded-full" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-3/4" />
                    <Skeleton className="h-3 w-1/2" />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="space-y-4">
              {(auditLogs?.items || []).length === 0 ? (
                <p className="py-8 text-center text-sm text-gray-500">
                  No recent activity
                </p>
              ) : (
                (auditLogs?.items || []).map((log) => (
                  <div
                    key={log.id}
                    className="flex items-start space-x-4 rounded-lg p-3 transition-colors hover:bg-gray-50"
                  >
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-purple-100">
                      <span className="text-sm font-medium text-purple-600">
                        {log.user.name.charAt(0).toUpperCase()}
                      </span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-gray-900">
                        {log.user.name}
                      </p>
                      <p className="text-sm text-gray-500">
                        {log.action} • {log.resource}
                      </p>
                      <p className="mt-1 text-xs text-gray-400">
                        {formatDistanceToNow(new Date(log.timestamp), {
                          addSuffix: true,
                        })}
                        {' • '}
                        {log.ip}
                      </p>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
