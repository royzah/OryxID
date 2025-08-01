# OryxID Frontend

A modern, elegant web application frontend for OryxID - an OAuth2/OpenID Connect server management dashboard.

## Features

- 🔐 **Authentication Management**: Secure login with JWT token handling
- 📱 **OAuth2 Application Management**: Create, edit, and manage OAuth2 client applications
- 🔑 **Scope Management**: Define and assign OAuth2 scopes
- 👥 **User Management**: Create and manage user accounts with role-based access
- 📊 **Dashboard**: Real-time statistics and activity monitoring
- 📝 **Audit Logs**: Track all system activities with filtering and export
- ⚙️ **Settings**: User profile, security settings, and preferences
- 🎨 **Modern UI**: Clean, minimalist design with smooth animations
- 📱 **Responsive**: Works seamlessly on desktop and mobile devices

## Tech Stack

- **Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS
- **State Management**: Zustand
- **API Client**: Axios with interceptors
- **Data Fetching**: TanStack Query (React Query)
- **Forms**: React Hook Form with Zod validation
- **Routing**: React Router v6
- **Components**: shadcn/ui (Radix UI + Tailwind)
- **Icons**: Lucide React
- **Date Handling**: date-fns
- **Charts**: Recharts

## Prerequisites

- Node.js 18+ and npm
- Backend server running on `http://localhost:9000`

## Installation

1. Install dependencies:

```bash
npm install
```

2. Set up environment variables:

Create a `.env` file in the frontend directory:

```env
VITE_API_URL=http://localhost:9000
```

## Development

Run the development server:

```bash
npm run dev
```

The application will be available at `http://localhost:3000`.

## Building for Production

Build the application:

```bash
npm run build
```

Preview the production build:

```bash
npm run preview
```

## Docker

Build and run with Docker:

```bash
# Build the image
docker build -t oryxid-frontend .

# Run the container
docker run -p 3000:80 oryxid-frontend
```

## Project Structure

```
src/
├── components/
│   ├── ui/              # shadcn/ui components
│   ├── layout/          # Layout components (Sidebar, Header)
│   ├── auth/            # Auth components (ProtectedRoute)
│   ├── applications/    # Application-specific components
│   ├── scopes/          # Scope-specific components
│   └── users/           # User-specific components
├── pages/
│   ├── auth/            # Login page
│   ├── applications/    # Applications & detail pages
│   ├── scopes/          # Scopes page
│   ├── users/           # Users page
│   ├── audit/           # Audit logs page
│   ├── dashboard/       # Dashboard page
│   └── settings/        # Settings page
├── hooks/               # Custom React hooks
├── lib/                 # Utilities (API client, utils)
├── services/            # API service layer
├── store/               # Zustand stores
├── types/               # TypeScript type definitions
└── styles/              # Global styles
```

## Available Pages

### Dashboard (`/`)
- Overview statistics
- Recent activity feed
- Quick access to main features

### Applications (`/applications`)
- List all OAuth2 applications
- Create new applications
- Search and filter
- Quick actions (edit, delete)

### Application Detail (`/applications/:id`)
- View and edit application details
- Manage client credentials
- Assign scopes
- Configure redirect URIs
- Token settings

### Scopes (`/scopes`)
- Grid view of all scopes
- Create and edit scopes
- Usage statistics
- Bulk operations

### Users (`/users`)
- User list with avatars
- Create new users
- Edit user details and roles
- Enable/disable accounts
- Search functionality

### Audit Logs (`/audit`)
- Timeline view of system events
- Advanced filtering (date, action, user)
- Export to CSV
- Expandable details

### Settings (`/settings`)
- Profile management
- Change password
- Active sessions
- Theme preferences
- Notification settings

## Key Features Implementation

### Authentication Flow
- JWT-based authentication
- Automatic token refresh
- Protected routes
- Session management

### Real-time Updates
- Dashboard statistics refresh every 30 seconds
- Activity feed updates
- Token expiration countdown

### Error Handling
- Global error interceptor
- Toast notifications
- Error boundaries
- Retry mechanisms

### Performance Optimizations
- Lazy loading for pages
- Query caching with React Query
- Debounced search inputs
- Memoized expensive operations

## Default Credentials

For development, use these credentials:

- Username: `admin`
- Password: `admin123`

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is part of OryxID and follows the same license terms.