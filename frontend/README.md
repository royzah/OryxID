# OryxID Frontend Documentation

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Getting Started](#getting-started)
3. [Project Structure](#project-structure)
4. [Configuration](#configuration)
5. [Component Guide](#component-guide)
6. [State Management](#state-management)
7. [API Integration](#api-integration)
8. [Styling Guide](#styling-guide)
9. [Development Workflow](#development-workflow)
10. [Testing](#testing)
11. [Performance Optimization](#performance-optimization)
12. [Build and Deployment](#build-and-deployment)
13. [Troubleshooting](#troubleshooting)

## Architecture Overview

The OryxID frontend is a modern single-page application built with React and TypeScript, designed for managing OAuth2/OpenID Connect configurations.

### Technology Stack

- **Framework**: React 18+ with TypeScript
- **Build Tool**: Vite 5+
- **Styling**: Tailwind CSS 3+ with Radix UI components
- **State Management**: Zustand 4+
- **Data Fetching**: TanStack Query (React Query) v5
- **Routing**: React Router v6
- **Form Handling**: React Hook Form
- **Date Handling**: date-fns
- **Icons**: Lucide React

### Key Features

- **Type-Safe Development**: Full TypeScript support with strict typing
- **Modern UI Components**: Built with Radix UI primitives and Tailwind CSS
- **Optimistic Updates**: Smooth user experience with TanStack Query
- **Secure Authentication**: JWT-based auth with automatic token refresh
- **Responsive Design**: Mobile-first approach with adaptive layouts
- **Dark Mode Support**: System-aware theme switching
- **Accessibility**: WCAG 2.1 AA compliant components

## Getting Started

### Prerequisites

- Node.js 18+ and npm 9+
- Git
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/tiiuae/oryxid.git
   cd oryxid/frontend
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Create environment configuration:

   ```bash
   cp .env.example .env
   # Edit .env with your API URL
   ```

4. Start development server:

   ```bash
   npm run dev
   ```

5. Open browser to [http://localhost:3000](http://localhost:3000)

### Quick Commands

```bash
# Development
npm run dev          # Start dev server with HMR
npm run build        # Build for production
npm run preview      # Preview production build
npm run type-check   # Run TypeScript compiler check

# Code Quality
npm run lint         # Run ESLint
npm run lint:fix     # Fix ESLint issues
npm run format       # Format code with Prettier

# Testing
npm run test         # Run tests
npm run test:watch   # Run tests in watch mode
npm run test:coverage # Generate coverage report
```

## Project Structure

```text
frontend/
├── public/                         # Static assets
│   └── favicon.ico
├── src/
│   ├── components/                 # React components
│   │   ├── ui/                     # Base UI components
│   │   │   ├── button.tsx
│   │   │   ├── dialog.tsx
│   │   │   └── ...
│   │   ├── Layout/                 # Layout components
│   │   ├── ApplicationDialog.tsx
│   │   ├── DeleteDialog.tsx
│   │   └── ...
│   ├── pages/                      # Page components
│   │   ├── Applications/
│   │   ├── Dashboard/
│   │   ├── Login/
│   │   └── ...
│   ├── services/                   # API services
│   │   └── api.ts
│   ├── stores/                     # State management
│   │   └── authStore.ts
│   ├── types/                      # TypeScript types
│   │   └── index.ts
│   ├── lib/                        # Utility functions
│   │   └── utils.ts
│   ├── App.tsx                     # Root component
│   ├── main.tsx                    # Application entry
│   └── index.css                   # Global styles
├── .env.example                    # Environment template
├── index.html                      # HTML template
├── package.json                    # Dependencies
├── tailwind.config.js              # Tailwind config
├── tsconfig.json                   # TypeScript config
└── vite.config.ts                  # Vite config
```

## Configuration

### Environment Variables

Create a `.env` file in the frontend directory:

```env
# API Configuration
VITE_API_URL=http://localhost:9000

# Feature Flags (optional)
VITE_ENABLE_ANALYTICS=false
VITE_ENABLE_DEBUG=true

# OAuth Client (for testing)
VITE_OAUTH_CLIENT_ID=your-client-id
VITE_OAUTH_REDIRECT_URI=http://localhost:3000/callback
```

### Build Configuration

#### Vite Configuration (`vite.config.ts`)

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://localhost:9000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          "react-vendor": ["react", "react-dom", "react-router-dom"],
          "ui-vendor": [
            "@radix-ui/react-dialog",
            "@radix-ui/react-dropdown-menu",
          ],
        },
      },
    },
  },
});
```

#### TypeScript Configuration (`tsconfig.json`)

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
```

## Component Guide

### UI Components

All base UI components are in `src/components/ui/` and follow these patterns:

#### Component Structure

```typescript
// Example: Button component
import * as React from "react"
import { cn } from "@/lib/utils"
import { buttonVariants } from "./variants"

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "destructive" | "outline" | "secondary" | "ghost" | "link"
  size?: "default" | "sm" | "lg" | "icon"
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
```

### Page Components

Pages follow a consistent structure:

```typescript
// Example: Applications page
export default function Applications() {
  // State management
  const [search, setSearch] = useState("")
  const [dialogOpen, setDialogOpen] = useState(false)

  // Data fetching
  const { data, isLoading } = useQuery({
    queryKey: ["applications", search],
    queryFn: () => applicationService.list({ search })
  })

  // Mutations
  const deleteMutation = useMutation({
    mutationFn: applicationService.delete,
    onSuccess: () => {
      queryClient.invalidateQueries(["applications"])
      toast({ title: "Success" })
    }
  })

  // Render
  return (
    <div className="space-y-6">
      {/* Page content */}
    </div>
  )
}
```

### Dialog Components

Dialogs use a standard pattern with React Hook Form:

```typescript
interface DialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  data?: DataType
  onSuccess: () => void
}

export default function DataDialog({ open, onOpenChange, data, onSuccess }: DialogProps) {
  const form = useForm<FormData>({
    defaultValues: { /* ... */ }
  })

  const mutation = useMutation({
    mutationFn: data ? updateData : createData,
    onSuccess: () => {
      toast({ title: "Success" })
      onSuccess()
    }
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {/* Dialog content */}
    </Dialog>
  )
}
```

## State Management

### Zustand Store Pattern

```typescript
// authStore.ts
interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;

  // Actions
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}

const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      // Initial state
      user: null,
      token: null,
      isAuthenticated: false,

      // Actions
      login: async (username, password) => {
        const response = await api.post("/auth/login", { username, password });
        const { token, user } = response.data;

        set({ token, user, isAuthenticated: true });
        api.defaults.headers.common["Authorization"] = `Bearer ${token}`;
      },

      logout: async () => {
        await api.post("/auth/logout");
        set({ user: null, token: null, isAuthenticated: false });
        delete api.defaults.headers.common["Authorization"];
      },
    }),
    {
      name: "auth-storage",
      partialize: (state) => ({ token: state.token }),
    }
  )
);
```

### Using Stores in Components

```typescript
function Component() {
  const { user, login, logout } = useAuthStore();

  // Use store state and actions
}
```

## API Integration

### Service Layer

All API calls go through service functions in `src/services/api.ts`:

```typescript
// Base configuration
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  headers: { "Content-Type": "application/json" },
});

// Interceptors
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Service functions
export const applicationService = {
  list: (params?: ListParams) =>
    api.get<Application[]>("/api/v1/applications", { params }),

  create: (data: CreateApplicationDto) =>
    api.post<Application>("/api/v1/applications", data),

  update: (id: string, data: UpdateApplicationDto) =>
    api.put<Application>(`/api/v1/applications/${id}`, data),

  delete: (id: string) => api.delete(`/api/v1/applications/${id}`),
};
```

### Using TanStack Query

```typescript
// Queries
const { data, isLoading, error } = useQuery({
  queryKey: ["applications", filters],
  queryFn: () => applicationService.list(filters),
  staleTime: 5 * 60 * 1000, // 5 minutes
});

// Mutations
const mutation = useMutation({
  mutationFn: applicationService.create,
  onSuccess: () => {
    queryClient.invalidateQueries(["applications"]);
    toast({ title: "Application created" });
  },
  onError: (error) => {
    toast({
      title: "Error",
      description: error.message,
      variant: "destructive",
    });
  },
});
```

## Styling Guide

### Tailwind CSS Classes

Follow these conventions:

```tsx
// Layout spacing
<div className="space-y-6">           {/* Vertical spacing */}
<div className="flex gap-4">          {/* Flexbox with gap */}
<div className="grid grid-cols-2">    {/* Grid layout */}

// Typography
<h1 className="text-2xl font-bold">   {/* Headings */}
<p className="text-sm text-gray-600"> {/* Body text */}

// Colors (with dark mode)
<div className="bg-white dark:bg-gray-800">
<p className="text-gray-900 dark:text-white">

// Interactive states
<button className="hover:bg-gray-100 focus:ring-2 focus:ring-primary">
```

### Component Styling Pattern

```tsx
// Use cn() utility for conditional classes
import { cn } from "@/lib/utils"

<div className={cn(
  "base-classes",
  isActive && "active-classes",
  isDisabled && "disabled-classes",
  className // Allow external overrides
)}>
```

### Responsive Design

```tsx
// Mobile-first approach
<div className="
  w-full          // Mobile
  md:w-1/2        // Tablet
  lg:w-1/3        // Desktop
  xl:w-1/4        // Large desktop
">
```

## Development Workflow

### 1. Feature Development

```bash
# 1. Create feature branch
git checkout -b feature/new-feature

# 2. Start dev server
npm run dev

# 3. Make changes with HMR

# 4. Run type checking
npm run type-check

# 5. Run linting
npm run lint:fix

# 6. Test your changes
npm run test
```

### 2. Component Development

Use the component template:

```typescript
// components/NewComponent.tsx
import { FC } from 'react'
import { cn } from '@/lib/utils'

interface NewComponentProps {
  className?: string
  // Add props
}

export const NewComponent: FC<NewComponentProps> = ({
  className,
  ...props
}) => {
  return (
    <div className={cn("default-classes", className)}>
      {/* Component content */}
    </div>
  )
}
```

### 3. Adding New Pages

1. Create page component in `src/pages/NewPage/index.tsx`
2. Add route in `App.tsx`
3. Add navigation item in `Layout/index.tsx`
4. Create any required API services
5. Add TypeScript types

## Testing

### Unit Tests

```typescript
// Button.test.tsx
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Button } from './Button'

describe('Button', () => {
  it('renders with text', () => {
    render(<Button>Click me</Button>)
    expect(screen.getByText('Click me')).toBeInTheDocument()
  })

  it('handles click events', async () => {
    const handleClick = vi.fn()
    render(<Button onClick={handleClick}>Click</Button>)

    await userEvent.click(screen.getByText('Click'))
    expect(handleClick).toHaveBeenCalledTimes(1)
  })
})
```

### Integration Tests

```typescript
// Applications.test.tsx
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Applications } from './Applications'

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } }
})

const wrapper = ({ children }) => (
  <QueryClientProvider client={queryClient}>
    {children}
  </QueryClientProvider>
)

describe('Applications Page', () => {
  it('loads and displays applications', async () => {
    render(<Applications />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Applications')).toBeInTheDocument()
    })
  })
})
```

## Performance Optimization

### Code Splitting

```typescript
// Lazy load pages
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Applications = lazy(() => import('./pages/Applications'))

// Use with Suspense
<Suspense fallback={<LoadingSpinner />}>
  <Routes>
    <Route path="/dashboard" element={<Dashboard />} />
    <Route path="/applications" element={<Applications />} />
  </Routes>
</Suspense>
```

### Memoization

```typescript
// Memoize expensive computations
const filteredData = useMemo(
  () => data?.filter((item) => item.name.includes(search)),
  [data, search]
);

// Memoize callbacks
const handleDelete = useCallback(
  (id: string) => {
    deleteMutation.mutate(id);
  },
  [deleteMutation]
);

// Memoize components
const MemoizedComponent = memo(ExpensiveComponent);
```

### Query Optimization

```typescript
// Prefetch data
const prefetchApplications = async () => {
  await queryClient.prefetchQuery({
    queryKey: ["applications"],
    queryFn: applicationService.list,
  });
};

// Optimistic updates
const mutation = useMutation({
  mutationFn: updateApplication,
  onMutate: async (newData) => {
    await queryClient.cancelQueries(["applications"]);
    const previousData = queryClient.getQueryData(["applications"]);

    queryClient.setQueryData(["applications"], (old) =>
      old.map((item) => (item.id === newData.id ? newData : item))
    );

    return { previousData };
  },
  onError: (err, newData, context) => {
    queryClient.setQueryData(["applications"], context.previousData);
  },
});
```

## Build and Deployment

### Development Build

```bash
# Standard build
npm run build

# Build with source maps
npm run build -- --sourcemap

# Build with analysis
npm run build -- --analyze
```

### Production Optimization

The build process automatically:

- Minifies JavaScript and CSS
- Optimizes images
- Generates source maps
- Splits vendor chunks
- Tree-shakes unused code
- Compresses assets with gzip/brotli

### Docker Build

```dockerfile
# Multi-stage build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
```

### Environment-Specific Builds

```bash
# Development
npm run build -- --mode development

# Staging
npm run build -- --mode staging

# Production
npm run build -- --mode production
```

### Deployment Checklist

- [ ] Run type checking: `npm run type-check`
- [ ] Run linting: `npm run lint`
- [ ] Run tests: `npm run test`
- [ ] Build application: `npm run build`
- [ ] Test production build: `npm run preview`
- [ ] Check bundle size
- [ ] Verify environment variables
- [ ] Test on target browsers
- [ ] Enable HTTPS
- [ ] Configure CSP headers
- [ ] Set up monitoring

## Troubleshooting

### Common Issues

#### 1. Build Errors

**Error**: `Cannot find module '@/components/ui/button'`

**Solution**: Check tsconfig.json paths configuration:

```json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
```

#### 2. API Connection Issues

**Error**: `Network Error` or CORS errors

**Solution**:

- Check VITE_API_URL in .env
- Ensure backend is running
- Verify CORS configuration on backend

#### 3. State Not Persisting

**Error**: User logged out on refresh

**Solution**: Check localStorage is not blocked:

```typescript
// Test localStorage availability
try {
  localStorage.setItem("test", "test");
  localStorage.removeItem("test");
} catch (e) {
  console.error("localStorage not available");
}
```

#### 4. Type Errors

**Error**: TypeScript compilation errors

**Solution**:

```bash
# Check types
npm run type-check

# Generate missing types
npm run generate-types
```

#### 5. Performance Issues

**Symptoms**: Slow renders, laggy UI

**Debug**:

```typescript
// Enable React DevTools Profiler
// Check for:
// - Unnecessary re-renders
// - Large component trees
// - Missing keys in lists
// - Unoptimized images

// Add performance monitoring
import { Profiler } from 'react'

<Profiler id="Applications" onRender={onRenderCallback}>
  <Applications />
</Profiler>
```

### Debug Mode

Enable debug mode for detailed logging:

```typescript
// In .env
VITE_ENABLE_DEBUG = true;

// In code
if (import.meta.env.VITE_ENABLE_DEBUG === "true") {
  console.log("Debug info:", data);
}
```

### Browser DevTools

1. **React Developer Tools**
   - Component tree inspection
   - Props and state debugging
   - Performance profiling

2. **Network Tab**
   - API request inspection
   - Response validation
   - Performance timing

3. **Console**
   - Error messages
   - Debug logging
   - API responses

### Getting Help

1. Check the [Backend README](../backend/README.md) for API issues
2. Review [React documentation](https://react.dev)
3. Check [Tailwind CSS docs](https://tailwindcss.com)
4. See [TanStack Query docs](https://tanstack.com/query)
