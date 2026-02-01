"""
Test Suite for Audit Service
============================
Tests for hash-chain audit logging and chain integrity verification.
"""

import pytest
import os
import json
import hashlib
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, AsyncMock

# Set test environment
os.environ['SUPABASE_URL'] = 'http://test.supabase.co'
os.environ['SUPABASE_SERVICE_ROLE_KEY'] = 'test_key_for_audit'

from backend.services.audit import (
    AuditService, AuditEventType, AuditEntry,
    AuditError, ChainIntegrityError
)


class TestAuditEntry:
    """Tests for AuditEntry dataclass."""
    
    def test_create_entry(self):
        """Test creating an audit entry."""
        entry = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            institution_id="inst-123",
            document_hash="hash456"
        )
        
        assert entry.event_type == AuditEventType.DOCUMENT_ISSUED
        assert entry.institution_id == "inst-123"
        assert entry.document_hash == "hash456"
        assert entry.created_at is not None
    
    def test_compute_hash_deterministic(self):
        """Test that hash computation is deterministic."""
        entry = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            institution_id="inst-123",
            document_hash="hash456",
            created_at="2026-02-01T12:00:00Z"
        )
        
        hash1 = entry.compute_hash()
        hash2 = entry.compute_hash()
        
        assert hash1 == hash2
    
    def test_compute_hash_changes_with_data(self):
        """Test that hash changes when data changes."""
        entry1 = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            institution_id="inst-123",
            document_hash="hash456",
            created_at="2026-02-01T12:00:00Z"
        )
        
        entry2 = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            institution_id="inst-123",
            document_hash="hash789",  # Different hash
            created_at="2026-02-01T12:00:00Z"
        )
        
        assert entry1.compute_hash() != entry2.compute_hash()
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        entry = AuditEntry(
            event_type=AuditEventType.KEY_ROTATED,
            institution_id="inst-999",
            metadata={"reason": "scheduled rotation"}
        )
        
        d = entry.to_dict()
        
        assert d["event_type"] == "key_rotated"
        assert d["institution_id"] == "inst-999"
        assert d["metadata"]["reason"] == "scheduled rotation"
    
    def test_hash_includes_chain_link(self):
        """Test that previous_log_hash is included in hash computation."""
        entry1 = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            previous_log_hash=None,
            created_at="2026-02-01T12:00:00Z"
        )
        
        entry2 = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            previous_log_hash="previous_hash_123",
            created_at="2026-02-01T12:00:00Z"
        )
        
        assert entry1.compute_hash() != entry2.compute_hash()


class TestAuditEventTypes:
    """Tests for audit event type enumeration."""
    
    def test_all_event_types_exist(self):
        """Test that all required event types are defined."""
        expected_types = [
            'institution_onboarded',
            'key_rotated',
            'document_issued',
            'document_revoked',
            'verification_success',
            'verification_failed',
            'template_created',
            'template_updated'
        ]
        
        for event_type in expected_types:
            assert AuditEventType(event_type) is not None
    
    def test_event_type_values(self):
        """Test event type enum values."""
        assert AuditEventType.DOCUMENT_ISSUED.value == "document_issued"
        assert AuditEventType.KEY_ROTATED.value == "key_rotated"


class TestAuditService:
    """Tests for AuditService class."""
    
    def test_initialization(self):
        """Test audit service initialization."""
        service = AuditService()
        assert service._supabase_url is not None
        assert service._supabase_key is not None
    
    def test_initialization_without_credentials(self):
        """Test service works without credentials (logs warning)."""
        with patch.dict(os.environ, {}, clear=True):
            service = AuditService(supabase_url=None, supabase_key=None)
            # Should not raise, just print warning
    
    @patch('backend.services.audit.httpx.get')
    @patch('backend.services.audit.httpx.post')
    def test_log_event(self, mock_post, mock_get):
        """Test logging an event."""
        # Mock the GET for previous entry
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = []
        
        # Mock the POST
        mock_post.return_value.status_code = 201
        
        service = AuditService()
        entry = service.log_event(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            institution_id="inst-123",
            document_hash="hash456"
        )
        
        assert entry is not None
        assert entry.event_type == AuditEventType.DOCUMENT_ISSUED
        assert entry.log_hash != ""
        assert entry.chain_position == 1  # First entry
    
    @patch('backend.services.audit.httpx.get')
    @patch('backend.services.audit.httpx.post')
    def test_log_event_with_previous_hash(self, mock_post, mock_get):
        """Test that logging fetches and links to previous hash."""
        # Mock existing entry
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [
            {"log_hash": "previous_hash_abc", "chain_position": 5}
        ]
        
        mock_post.return_value.status_code = 201
        
        service = AuditService()
        entry = service.log_event(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            institution_id="inst-123"
        )
        
        assert entry is not None
        assert entry.previous_log_hash == "previous_hash_abc"
        assert entry.chain_position == 6  # Previous + 1
    
    @patch('backend.services.audit.httpx.get')
    @patch('backend.services.audit.httpx.post')
    def test_log_document_issued_helper(self, mock_post, mock_get):
        """Test the document issued helper method."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = []
        mock_post.return_value.status_code = 201
        
        service = AuditService()
        entry = service.log_document_issued(
            institution_id="inst-789",
            document_id="doc-123",
            document_hash="hash999",
            signature="sig123abc",
            document_type="academic"
        )
        
        assert entry is not None
        assert entry.event_type == AuditEventType.DOCUMENT_ISSUED
        assert "signature" in entry.metadata
        assert entry.metadata["document_type"] == "academic"
    
    @patch('backend.services.audit.httpx.get')
    @patch('backend.services.audit.httpx.post')
    def test_log_verification_success(self, mock_post, mock_get):
        """Test logging successful verification."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = []
        mock_post.return_value.status_code = 201
        
        service = AuditService()
        entry = service.log_verification(
            document_hash="verified_hash",
            is_valid=True,
            ip_address="192.168.1.1"
        )
        
        assert entry is not None
        assert entry.event_type == AuditEventType.VERIFICATION_SUCCESS
        assert entry.ip_address == "192.168.1.1"
    
    @patch('backend.services.audit.httpx.get')
    @patch('backend.services.audit.httpx.post')
    def test_log_verification_failure(self, mock_post, mock_get):
        """Test logging failed verification."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = []
        mock_post.return_value.status_code = 201
        
        service = AuditService()
        entry = service.log_verification(
            document_hash="bad_hash",
            is_valid=False,
            failure_reason="Signature mismatch"
        )
        
        assert entry is not None
        assert entry.event_type == AuditEventType.VERIFICATION_FAILED
        assert entry.metadata.get("failure_reason") == "Signature mismatch"


class TestChainIntegrity:
    """Tests for audit chain integrity verification."""
    
    @patch('backend.services.audit.httpx.get')
    def test_verify_empty_chain(self, mock_get):
        """Test verifying an empty chain."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = []
        
        service = AuditService()
        is_valid, broken_at = service.verify_chain_integrity()
        
        assert is_valid is True
        assert broken_at is None
    
    @patch('backend.services.audit.httpx.get')
    def test_verify_valid_chain(self, mock_get):
        """Test verifying a valid chain."""
        # Create a valid chain
        entries = [
            {"log_hash": "hash1", "previous_log_hash": None, "chain_position": 1},
            {"log_hash": "hash2", "previous_log_hash": "hash1", "chain_position": 2},
            {"log_hash": "hash3", "previous_log_hash": "hash2", "chain_position": 3}
        ]
        
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = entries
        
        service = AuditService()
        is_valid, broken_at = service.verify_chain_integrity()
        
        assert is_valid is True
        assert broken_at is None
    
    @patch('backend.services.audit.httpx.get')
    def test_verify_broken_chain(self, mock_get):
        """Test detecting a broken chain."""
        # Chain with broken link at position 3
        entries = [
            {"log_hash": "hash1", "previous_log_hash": None, "chain_position": 1},
            {"log_hash": "hash2", "previous_log_hash": "hash1", "chain_position": 2},
            {"log_hash": "hash3", "previous_log_hash": "WRONG_HASH", "chain_position": 3}
        ]
        
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = entries
        
        service = AuditService()
        is_valid, broken_at = service.verify_chain_integrity()
        
        assert is_valid is False
        assert broken_at == 3
    
    @patch('backend.services.audit.httpx.get')
    def test_verify_chain_middle_entry_deleted(self, mock_get):
        """Test detecting when a middle entry is deleted."""
        # Chain with position 2 missing
        entries = [
            {"log_hash": "hash1", "previous_log_hash": None, "chain_position": 1},
            {"log_hash": "hash3", "previous_log_hash": "hash2", "chain_position": 3}
        ]
        
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = entries
        
        service = AuditService()
        is_valid, broken_at = service.verify_chain_integrity()
        
        # Should detect the break
        assert is_valid is False


class TestAuditTrailRetrieval:
    """Tests for retrieving audit trail."""
    
    @patch('backend.services.audit.httpx.get')
    def test_get_audit_trail_basic(self, mock_get):
        """Test basic audit trail retrieval."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [
            {"event_type": "document_issued", "document_hash": "hash1"},
            {"event_type": "document_issued", "document_hash": "hash2"}
        ]
        
        service = AuditService()
        entries = service.get_audit_trail(limit=10)
        
        assert len(entries) == 2
    
    @patch('backend.services.audit.httpx.get')
    def test_get_audit_trail_with_filters(self, mock_get):
        """Test audit trail with filters applied."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = []
        
        service = AuditService()
        entries = service.get_audit_trail(
            institution_id="inst-123",
            event_type=AuditEventType.DOCUMENT_ISSUED,
            limit=50
        )
        
        # Verify the call was made with filters
        call_args = mock_get.call_args
        assert "institution_id" in str(call_args)


class TestHashChainSecurity:
    """Security-focused tests for the hash chain."""
    
    def test_tampering_changes_hash(self):
        """Test that any tampering changes the entry hash."""
        entry = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            institution_id="inst-123",
            document_hash="original_hash",
            chain_position=5,
            created_at="2026-02-01T12:00:00Z"
        )
        
        original_log_hash = entry.compute_hash()
        
        # Simulate tampering
        entry.document_hash = "tampered_hash"
        tampered_log_hash = entry.compute_hash()
        
        assert original_log_hash != tampered_log_hash
    
    def test_position_change_changes_hash(self):
        """Test that changing position changes the hash."""
        entry = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            chain_position=5,
            created_at="2026-02-01T12:00:00Z"
        )
        
        hash1 = entry.compute_hash()
        
        entry.chain_position = 10
        hash2 = entry.compute_hash()
        
        assert hash1 != hash2
    
    def test_timestamp_change_changes_hash(self):
        """Test that changing timestamp changes the hash."""
        entry1 = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            created_at="2026-02-01T12:00:00Z"
        )
        
        entry2 = AuditEntry(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            created_at="2026-02-01T12:00:01Z"  # 1 second later
        )
        
        assert entry1.compute_hash() != entry2.compute_hash()
