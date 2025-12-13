# Nginx with bundled configuration
FROM nginx:alpine

# Copy configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/default.conf /etc/nginx/conf.d/default.conf

# Create directories for certificates and ACME challenges
RUN mkdir -p /etc/nginx/ssl /var/www/certbot

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost/health || exit 1

EXPOSE 80 443
