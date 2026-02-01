"""Legacy audit log tests - updated for new audit service."""
import os
import httpx
from unittest.mock import patch, MagicMock

# Set test environment
os.environ["SUPABASE_URL"] = "http://test.com"
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = "secret"

from backend.services.audit import AuditService, AuditEventType

@patch("backend.services.audit.httpx.post")
@patch("backend.services.audit.httpx.get")
def test_audit_log_hash_chain(mock_get, mock_post):
    """Test that audit service creates hash chain links."""
    # Mock previous entry
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = [{"log_hash": "prev_hash_123", "chain_position": 5}]

    # Mock post response
    mock_post.return_value.status_code = 201

    service = AuditService()
    entry = service.log_event(
        event_type=AuditEventType.DOCUMENT_ISSUED,
        document_hash="current_hash_456"
    )

    # Check that entry was created with chain link
    assert entry is not None
    assert entry.previous_log_hash == "prev_hash_123"
    assert entry.chain_position == 6
    assert entry.document_hash == "current_hash_456"

@patch("backend.services.audit.httpx.post")
@patch("backend.services.audit.httpx.get")
def test_audit_log_no_previous_hash(mock_get, mock_post):
    """Test audit log for first entry (no previous hash)."""
    # Mock no previous entry
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = []

    mock_post.return_value.status_code = 201

    service = AuditService()
    entry = service.log_event(
        event_type=AuditEventType.DOCUMENT_ISSUED,
        document_hash="first_hash_789"
    )

    assert entry is not None
    assert entry.document_hash == "first_hash_789"
    assert entry.previous_log_hash is None
    assert entry.chain_position == 1
