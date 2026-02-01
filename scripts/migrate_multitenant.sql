-- ================================================
-- Multi-Tenant CertiTrust Database Schema
-- Version: 2.0.0
-- Date: 2026-02-01
-- Description: Tables for multi-tenant document issuance platform
-- ================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ================================================
-- INSTITUTIONS TABLE (Multi-Tenant Core)
-- ================================================
CREATE TABLE IF NOT EXISTS institutions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    slug TEXT NOT NULL UNIQUE,  -- URL-friendly identifier
    
    -- Ed25519 Key Management
    public_key_pem TEXT NOT NULL,           -- PEM encoded public key (visible)
    encrypted_private_key TEXT NOT NULL,    -- AES-256-GCM encrypted private key
    key_nonce TEXT NOT NULL,                -- Nonce used for encryption
    
    -- Metadata
    contact_email TEXT,
    domain TEXT,                            -- Institution's domain for verification
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    key_rotated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast lookup
CREATE INDEX IF NOT EXISTS idx_institutions_slug ON institutions(slug);
CREATE INDEX IF NOT EXISTS idx_institutions_active ON institutions(is_active);

-- ================================================
-- DOCUMENT TEMPLATES TABLE
-- ================================================
CREATE TABLE IF NOT EXISTS document_templates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    
    -- Template Identity
    name TEXT NOT NULL,
    template_type TEXT NOT NULL CHECK (template_type IN ('aadhaar', 'academic', 'permit', 'generic', 'w3c_vc')),
    version TEXT DEFAULT '1.0.0',
    
    -- Schema & Configuration
    json_schema JSONB,                      -- JSON Schema for validation
    ld_context JSONB,                       -- JSON-LD @context for W3C VC
    required_fields TEXT[],                 -- List of required field names
    
    -- Display Configuration
    display_name TEXT,
    description TEXT,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Unique constraint per institution
    UNIQUE(institution_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_templates_institution ON document_templates(institution_id);
CREATE INDEX IF NOT EXISTS idx_templates_type ON document_templates(template_type);

-- ================================================
-- ISSUED DOCUMENTS TABLE (Enhanced)
-- ================================================
CREATE TABLE IF NOT EXISTS issued_documents (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    institution_id UUID NOT NULL REFERENCES institutions(id) ON DELETE CASCADE,
    template_id UUID REFERENCES document_templates(id) ON DELETE SET NULL,
    
    -- Document Identity
    document_hash TEXT NOT NULL,            -- SHA-256 of original document
    signature TEXT NOT NULL,                -- Ed25519 signature (base64)
    
    -- Merkle Tree for Multi-Page PDFs
    merkle_root TEXT,                       -- Root hash for multi-page documents
    page_hashes JSONB,                      -- Array of {page_num, hash}
    
    -- Metadata
    subject_id TEXT,                        -- Identifier of document subject (hashed for privacy)
    document_type TEXT,
    file_name TEXT,
    
    -- Status
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    
    -- Timestamps
    issued_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    
    -- Unique constraint
    UNIQUE(institution_id, document_hash)
);

CREATE INDEX IF NOT EXISTS idx_issued_docs_institution ON issued_documents(institution_id);
CREATE INDEX IF NOT EXISTS idx_issued_docs_hash ON issued_documents(document_hash);
CREATE INDEX IF NOT EXISTS idx_issued_docs_status ON issued_documents(status);

-- ================================================
-- AUDIT LOGS TABLE (Enhanced with Hash Chain)
-- ================================================
DROP TABLE IF EXISTS audit_logs CASCADE;

CREATE TABLE audit_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    institution_id UUID REFERENCES institutions(id) ON DELETE SET NULL,
    
    -- Event Details
    event_type TEXT NOT NULL CHECK (event_type IN (
        'institution_onboarded',
        'key_rotated',
        'document_issued',
        'document_revoked',
        'verification_success',
        'verification_failed',
        'template_created',
        'template_updated'
    )),
    
    -- Document Reference
    document_id UUID REFERENCES issued_documents(id) ON DELETE SET NULL,
    document_hash TEXT,
    
    -- Hash Chain for Tamper Detection
    log_hash TEXT NOT NULL,                 -- SHA-256 of this log entry
    previous_log_hash TEXT,                 -- Reference to previous entry's log_hash
    chain_position BIGINT,                  -- Sequential position in the chain
    
    -- Metadata
    actor_id TEXT,                          -- Who performed the action
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,                         -- Additional context
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_institution ON audit_logs(institution_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_document ON audit_logs(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_chain_position ON audit_logs(institution_id, chain_position DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);

-- ================================================
-- VERIFICATION SESSIONS TABLE
-- ================================================
CREATE TABLE IF NOT EXISTS verification_sessions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    
    -- Verification Details
    document_hash TEXT NOT NULL,
    institution_id UUID REFERENCES institutions(id) ON DELETE SET NULL,
    
    -- Result
    is_valid BOOLEAN,
    verification_method TEXT,               -- 'qr_scan', 'file_upload', 'api'
    failure_reason TEXT,
    
    -- Session Info
    session_token TEXT UNIQUE,
    ip_address INET,
    user_agent TEXT,
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_verification_hash ON verification_sessions(document_hash);
CREATE INDEX IF NOT EXISTS idx_verification_token ON verification_sessions(session_token);

-- ================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ================================================
-- Enable RLS on all tables
ALTER TABLE institutions ENABLE ROW LEVEL SECURITY;
ALTER TABLE document_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE issued_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE verification_sessions ENABLE ROW LEVEL SECURITY;

-- Service role has full access (for backend operations)
CREATE POLICY "Service role full access on institutions" 
    ON institutions FOR ALL 
    USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access on document_templates" 
    ON document_templates FOR ALL 
    USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access on issued_documents" 
    ON issued_documents FOR ALL 
    USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access on audit_logs" 
    ON audit_logs FOR ALL 
    USING (auth.role() = 'service_role');

CREATE POLICY "Service role full access on verification_sessions" 
    ON verification_sessions FOR ALL 
    USING (auth.role() = 'service_role');

-- Public read access for verification
CREATE POLICY "Public can verify documents" 
    ON issued_documents FOR SELECT 
    USING (status = 'active');

CREATE POLICY "Public can read institution public keys" 
    ON institutions FOR SELECT 
    USING (is_active = TRUE);

-- ================================================
-- FUNCTIONS FOR AUDIT LOG HASH CHAIN
-- ================================================
CREATE OR REPLACE FUNCTION get_next_chain_position(inst_id UUID)
RETURNS BIGINT AS $$
DECLARE
    next_pos BIGINT;
BEGIN
    SELECT COALESCE(MAX(chain_position), 0) + 1 
    INTO next_pos 
    FROM audit_logs 
    WHERE institution_id = inst_id;
    
    RETURN next_pos;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_previous_log_hash(inst_id UUID)
RETURNS TEXT AS $$
DECLARE
    prev_hash TEXT;
BEGIN
    SELECT log_hash 
    INTO prev_hash 
    FROM audit_logs 
    WHERE institution_id = inst_id
    ORDER BY chain_position DESC 
    LIMIT 1;
    
    RETURN prev_hash;
END;
$$ LANGUAGE plpgsql;

-- ================================================
-- TRIGGER FOR UPDATED_AT TIMESTAMPS
-- ================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_institutions_updated_at
    BEFORE UPDATE ON institutions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_document_templates_updated_at
    BEFORE UPDATE ON document_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ================================================
-- SEED DATA: Default Templates
-- ================================================
-- Note: These will be inserted after an institution is onboarded
-- Example W3C VC Context for Academic Credentials
COMMENT ON TABLE document_templates IS 'Stores document templates including W3C Verifiable Credentials schemas';

-- ================================================
-- MIGRATION COMPLETE
-- ================================================
