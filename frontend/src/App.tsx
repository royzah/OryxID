import { lazy, Suspense } from 'react';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { Toaster } from 'sonner';
import './index.css';
import { AuthGuard } from '@/components/auth/AuthGuard';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { MainLayout } from '@/components/layout/MainLayout';
import { Loader2 } from 'lucide-react';

// Lazy load pages
const LoginPage = lazy(() =>
  import('@/pages/auth/LoginPage').then((m) => ({ default: m.LoginPage })),
);
const DashboardPage = lazy(() =>
  import('@/pages/dashboard/DashboardPage').then((m) => ({
    default: m.DashboardPage,
  })),
);
const ApplicationsPage = lazy(() =>
  import('@/pages/applications/ApplicationsPage').then((m) => ({
    default: m.ApplicationsPage,
  })),
);
const ApplicationDetailPage = lazy(() =>
  import('@/pages/applications/ApplicationDetailPage').then((m) => ({
    default: m.ApplicationDetailPage,
  })),
);
const ScopesPage = lazy(() =>
  import('@/pages/scopes/ScopesPage').then((m) => ({ default: m.ScopesPage })),
);
const UsersPage = lazy(() =>
  import('@/pages/users/UsersPage').then((m) => ({ default: m.UsersPage })),
);
const AuditPage = lazy(() =>
  import('@/pages/audit/AuditPage').then((m) => ({ default: m.AuditPage })),
);
const SettingsPage = lazy(() =>
  import('@/pages/settings/SettingsPage').then((m) => ({
    default: m.SettingsPage,
  })),
);

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      gcTime: 1000 * 60 * 10, // 10 minutes
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

// Loading component
const PageLoader = () => (
  <div className="flex h-96 items-center justify-center">
    <Loader2 className="h-8 w-8 animate-spin text-purple-600" />
  </div>
);

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <AuthGuard>
          <Suspense fallback={<PageLoader />}>
            <Routes>
              {/* Public routes */}
              <Route path="/login" element={<LoginPage />} />

              {/* Protected routes */}
              <Route
                element={
                  <ProtectedRoute>
                    <MainLayout />
                  </ProtectedRoute>
                }
              >
                <Route path="/" element={<DashboardPage />} />
                <Route path="/applications" element={<ApplicationsPage />} />
                <Route
                  path="/applications/:id"
                  element={<ApplicationDetailPage />}
                />
                <Route path="/scopes" element={<ScopesPage />} />
                <Route path="/users" element={<UsersPage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Route>

              {/* Catch all route */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </AuthGuard>
      </Router>

      <Toaster position="top-right" richColors closeButton theme="light" />

      {import.meta.env.DEV && <ReactQueryDevtools />}
    </QueryClientProvider>
  );
}

export default App;
