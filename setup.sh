#!/bin/bash

# OryxID Setup Script
# This script performs initial setup for the OryxID project

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}       OryxID Initial Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed!${NC}"
    echo "Please install Docker from https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not installed!${NC}"
    echo "Please install Docker Compose from https://docs.docker.com/compose/install/"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file from template...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env file${NC}"
    echo
    echo -e "${YELLOW}IMPORTANT: Please review and update the .env file:${NC}"
    echo "  - Change default passwords"
    echo "  - Update admin credentials"
    echo "  - Configure OAuth settings"
    echo
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

# Generate RSA keys
echo -e "${YELLOW}Generating RSA keys for JWT signing...${NC}"
mkdir -p certs

if [ ! -f certs/private_key.pem ]; then
    openssl genrsa -out certs/private_key.pem 4096 2>/dev/null
    echo -e "${GREEN}✓ Generated private key${NC}"
else
    echo -e "${YELLOW}  Private key already exists, skipping...${NC}"
fi

if [ ! -f certs/public_key.pem ]; then
    openssl rsa -in certs/private_key.pem -pubout -out certs/public_key.pem 2>/dev/null
    echo -e "${GREEN}✓ Generated public key${NC}"
else
    echo -e "${YELLOW}  Public key already exists, skipping...${NC}"
fi

echo
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}       Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo
echo "Next steps:"
echo "  1. Review and update the .env file"
echo "  2. Run 'make up' to start all services"
echo "  3. Access the admin panel at http://localhost:3000"
echo
echo "Default admin credentials (change these!):"
echo "  Username: admin"
echo "  Password: admin123"
echo
