-- ================================================
-- CertiTrust Institution API Keys Migration
-- ================================================
-- This migration adds API key-based authentication for institutions.
--
-- Security Design:
-- - API keys are never stored in plaintext
-- - Only SHA-256 hash of the key is stored
-- - Keys can be time-limited and rate-limited
-- - Audit trail for key usage
--
-- Run this AFTER migrate_multitenant.sql

-- ================================================
-- INSTITUTION API KEYS TABLE
-- ================================================
CREATE TABLE IF NOT EXISTS institution_api_keys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    
    -- Key Identity
    name TEXT NOT NULL DEFAULT 'Default Key',
    key_hash TEXT NOT NULL,                 -- SHA-256 hash of API key (64 chars)
    key_prefix TEXT NOT NULL,               -- First 12 chars for identification
    
    -- Access Control
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ,                 -- NULL = never expires
    
    -- Rate Limiting
    rate_limit_per_day INTEGER,             -- NULL = unlimited
    daily_request_count INTEGER DEFAULT 0,
    last_request_date DATE,
    
    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    
    -- Ensure unique hashes
    UNIQUE(key_hash)
);

-- Indexes for fast lookup
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON institution_api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_institution ON institution_api_keys(institution_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON institution_api_keys(is_active) WHERE is_active = TRUE;

-- ================================================
-- COMMENTS
-- ================================================
COMMENT ON TABLE institution_api_keys IS 'Stores hashed API keys for institution authentication';
COMMENT ON COLUMN institution_api_keys.key_hash IS 'SHA-256 hash of the full API key (never store plaintext)';
COMMENT ON COLUMN institution_api_keys.key_prefix IS 'First 12 characters of API key for identification (ctrust_xxxx)';
COMMENT ON COLUMN institution_api_keys.rate_limit_per_day IS 'Maximum requests per day (NULL for unlimited)';

-- ================================================
-- TRIGGER: Update last_used_at on access
-- ================================================
CREATE OR REPLACE FUNCTION update_api_key_usage()
RETURNS TRIGGER AS $$
BEGIN
    -- This is called when daily_request_count is updated
    NEW.last_used_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_api_key_usage ON institution_api_keys;
CREATE TRIGGER trigger_api_key_usage
    BEFORE UPDATE OF daily_request_count ON institution_api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_api_key_usage();

-- ================================================
-- RLS POLICIES (Row Level Security)
-- ================================================
-- Enable RLS on the table
ALTER TABLE institution_api_keys ENABLE ROW LEVEL SECURITY;

-- Policy: Service role has full access
CREATE POLICY "Service role can manage all API keys"
    ON institution_api_keys
    FOR ALL
    USING (auth.jwt() ->> 'role' = 'service_role');

-- Policy: Institutions can only see their own keys (metadata only)
CREATE POLICY "Institutions can view own keys"
    ON institution_api_keys
    FOR SELECT
    USING (institution_id = (auth.jwt() ->> 'institution_id')::uuid);

-- ================================================
-- SAMPLE: Create first API key for existing institutions
-- ================================================
-- Uncomment to auto-generate keys for existing institutions
-- (Keys will be hashed, you'll need to regenerate them via API)

-- INSERT INTO institution_api_keys (institution_id, name, key_hash, key_prefix)
-- SELECT id, 'Auto-generated Key', 
--        encode(sha256('placeholder_' || id::text), 'hex'),
--        'ctrust_auto_'
-- FROM institutions
-- WHERE NOT EXISTS (
--     SELECT 1 FROM institution_api_keys WHERE institution_id = institutions.id
-- );

-- ================================================
-- SUCCESS MESSAGE
-- ================================================
DO $$ 
BEGIN 
    RAISE NOTICE 'Institution API Keys migration completed successfully!';
    RAISE NOTICE 'Use the /institutions/{id}/api-keys endpoint to generate API keys.';
END $$;
