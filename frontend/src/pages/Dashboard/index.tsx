import { useQuery } from "@tanstack/react-query";
import {
  Package,
  Users,
  Key,
  Shield,
  Activity,
  TrendingUp,
} from "lucide-react";
import { statsService } from "../../services/api";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "../../components/ui/card";

export default function Dashboard() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ["stats"],
    queryFn: async () => {
      const response = await statsService.get();
      return response.data;
    },
  });

  const cards = [
    {
      title: "Applications",
      value: stats?.applications || 0,
      icon: Package,
      description: "Active OAuth clients",
      color: "text-blue-600",
      bgColor: "bg-blue-100",
    },
    {
      title: "Users",
      value: stats?.users || 0,
      icon: Users,
      description: "System administrators",
      color: "text-green-600",
      bgColor: "bg-green-100",
    },
    {
      title: "Scopes",
      value: stats?.scopes || 0,
      icon: Key,
      description: "Available permissions",
      color: "text-purple-600",
      bgColor: "bg-purple-100",
    },
    {
      title: "Audiences",
      value: stats?.audiences || 0,
      icon: Shield,
      description: "API audiences",
      color: "text-orange-600",
      bgColor: "bg-orange-100",
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          Dashboard
        </h1>
        <p className="mt-2 text-gray-600 dark:text-gray-400">
          Welcome to OryxID OAuth2/OIDC Server
        </p>
      </div>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div
              key={i}
              className="h-32 bg-gray-200 dark:bg-gray-700 animate-pulse rounded-lg"
            />
          ))}
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {cards.map((card) => (
            <Card key={card.title}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  {card.title}
                </CardTitle>
                <div className={`p-2 rounded-full ${card.bgColor}`}>
                  <card.icon className={`h-4 w-4 ${card.color}`} />
                </div>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{card.value}</div>
                <p className="text-xs text-muted-foreground">
                  {card.description}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              System Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  API Server
                </span>
                <span className="flex items-center gap-2 text-sm">
                  <span className="h-2 w-2 bg-green-500 rounded-full animate-pulse"></span>
                  Operational
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  Database
                </span>
                <span className="flex items-center gap-2 text-sm">
                  <span className="h-2 w-2 bg-green-500 rounded-full animate-pulse"></span>
                  Connected
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  Cache
                </span>
                <span className="flex items-center gap-2 text-sm">
                  <span className="h-2 w-2 bg-green-500 rounded-full animate-pulse"></span>
                  Active
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  Active Tokens
                </span>
                <span className="text-sm font-medium">
                  {stats?.active_tokens || 0}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              Quick Actions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <a
                href="/applications"
                className="block p-3 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                <div className="font-medium">Create New Application</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Register a new OAuth2 client
                </div>
              </a>
              <a
                href="/scopes"
                className="block p-3 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                <div className="font-medium">Manage Scopes</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Configure available permissions
                </div>
              </a>
              <a
                href="/audit-logs"
                className="block p-3 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              >
                <div className="font-medium">View Audit Logs</div>
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  Monitor system activity
                </div>
              </a>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
