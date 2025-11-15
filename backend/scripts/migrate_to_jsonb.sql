-- Migration script to update existing database schema to use JSONB
-- This script is idempotent and can be run safely multiple times

-- Migrate applications table from TEXT[] to JSONB
DO $$
BEGIN
    -- Check if grant_types column exists and is of type TEXT[]
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'applications'
        AND column_name = 'grant_types'
        AND data_type = 'ARRAY'
    ) THEN
        -- Convert TEXT[] columns to JSONB
        ALTER TABLE applications
            ALTER COLUMN grant_types TYPE JSONB USING
                CASE
                    WHEN grant_types IS NULL THEN '[]'::jsonb
                    ELSE array_to_json(grant_types)::jsonb
                END,
            ALTER COLUMN grant_types SET DEFAULT '[]'::jsonb;

        ALTER TABLE applications
            ALTER COLUMN response_types TYPE JSONB USING
                CASE
                    WHEN response_types IS NULL THEN '[]'::jsonb
                    ELSE array_to_json(response_types)::jsonb
                END,
            ALTER COLUMN response_types SET DEFAULT '[]'::jsonb;

        ALTER TABLE applications
            ALTER COLUMN redirect_uris TYPE JSONB USING
                CASE
                    WHEN redirect_uris IS NULL THEN '[]'::jsonb
                    ELSE array_to_json(redirect_uris)::jsonb
                END,
            ALTER COLUMN redirect_uris SET DEFAULT '[]'::jsonb;

        ALTER TABLE applications
            ALTER COLUMN post_logout_uris TYPE JSONB USING
                CASE
                    WHEN post_logout_uris IS NULL THEN '[]'::jsonb
                    ELSE array_to_json(post_logout_uris)::jsonb
                END,
            ALTER COLUMN post_logout_uris SET DEFAULT '[]'::jsonb;

        RAISE NOTICE 'Successfully migrated applications table to JSONB';
    ELSE
        RAISE NOTICE 'Applications table already uses JSONB or does not exist';
    END IF;
END $$;

-- Migrate audit_logs table schema
DO $$
BEGIN
    -- Check if resource_type column exists (old schema)
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_logs'
        AND column_name = 'resource_type'
    ) THEN
        -- Rename resource_type to resource
        ALTER TABLE audit_logs RENAME COLUMN resource_type TO resource;

        -- Rename details to metadata
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_logs'
            AND column_name = 'details'
        ) THEN
            ALTER TABLE audit_logs RENAME COLUMN details TO metadata;
        END IF;

        -- Add status_code column if it doesn't exist
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'audit_logs'
            AND column_name = 'status_code'
        ) THEN
            ALTER TABLE audit_logs ADD COLUMN status_code INTEGER;
        END IF;

        RAISE NOTICE 'Successfully migrated audit_logs table schema';
    ELSE
        RAISE NOTICE 'Audit_logs table already has correct schema or does not exist';
    END IF;
END $$;

-- Add missing columns to tokens table
DO $$
BEGIN
    -- Add audience column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tokens'
        AND column_name = 'audience'
    ) THEN
        ALTER TABLE tokens ADD COLUMN audience TEXT;
        RAISE NOTICE 'Added audience column to tokens table';
    END IF;

    -- Add revoked_at column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tokens'
        AND column_name = 'revoked_at'
    ) THEN
        ALTER TABLE tokens ADD COLUMN revoked_at TIMESTAMP WITH TIME ZONE;
        RAISE NOTICE 'Added revoked_at column to tokens table';
    END IF;

    RAISE NOTICE 'Tokens table schema is up to date';
END $$;
