# syntax=docker/dockerfile:1

# Development Stage
FROM node:20-alpine AS development
WORKDIR /app

# Install dependencies
COPY package*.json ./
# Use legacy peer deps to handle ESLint version conflicts
RUN npm ci --legacy-peer-deps

# Copy source code
COPY . .

# Expose development port
EXPOSE 3000

# Development command with hot-reload
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]

# Build Stage
FROM node:20-alpine AS build
WORKDIR /app

# Install dependencies
COPY package*.json ./
# Use legacy peer deps to handle ESLint version conflicts
RUN npm ci --legacy-peer-deps

# Copy source and build
COPY . .

# Build the application
RUN npm run build

# Production Stage
FROM nginx:alpine AS production

# Copy built files
COPY --from=build /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost/health || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]