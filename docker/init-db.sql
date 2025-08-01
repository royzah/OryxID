-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set default permissions
GRANT ALL PRIVILEGES ON DATABASE oryxid TO oryxid;