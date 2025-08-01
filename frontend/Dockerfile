# syntax=docker/dockerfile:1

########################################
# ——— Development Stage ———————
########################################
FROM node:20.10.16-alpine3.16 AS dev

# Ensure LF line endings; no inline comments on FROM
WORKDIR /app

# Cache dependencies install when package files change
COPY package*.json ./
RUN npm ci

# Copy everything else and expose dev server
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]

########################################
# ——— Build Stage ——————————
########################################
FROM node:20.10.16-alpine3.16 AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

########################################
# ——— Production Stage (Distroless) ———
########################################
# Use a distroless static image for minimal runtime
FROM gcr.io/distroless/static-debian12 AS production

# Copy only the build output
COPY --from=build /app/dist /app/dist

# Create non-root user for runtime
USER nonroot

# Expose HTTP port
EXPOSE 80

# Simple healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --quiet --spider http://localhost/app/dist || exit 1

# Serve static files with a simple HTTP server
CMD ["./app/dist"]
