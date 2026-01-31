import os
import httpx
from unittest.mock import patch, MagicMock
from backend.main import log_audit_event

@patch("backend.main.httpx.post")
@patch("backend.main.httpx.get")
def test_audit_log_hash_chain(mock_get, mock_post):
    # Setup env
    os.environ["SUPABASE_URL"] = "http://test.com"
    os.environ["SUPABASE_SERVICE_ROLE_KEY"] = "secret"

    # Mock previous entry
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = [{"document_hash": "prev_hash_123"}]

    # Mock post response
    mock_post.return_value.status_code = 201

    log_audit_event("current_hash_456")

    # Check GET call
    mock_get.assert_called_once()
    args, kwargs = mock_get.call_args
    assert "audit_logs" in args[0]
    assert "order=created_at.desc" in args[0]

    # Check POST call
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    data = kwargs['json']
    assert data['document_hash'] == "current_hash_456"
    assert data['previous_hash'] == "prev_hash_123"
    assert "issuance_date" in data

@patch("backend.main.httpx.post")
@patch("backend.main.httpx.get")
def test_audit_log_no_previous_hash(mock_get, mock_post):
    os.environ["SUPABASE_URL"] = "http://test.com"
    os.environ["SUPABASE_SERVICE_ROLE_KEY"] = "secret"

    # Mock no previous entry
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = []

    mock_post.return_value.status_code = 201

    log_audit_event("first_hash_789")

    args, kwargs = mock_post.call_args
    data = kwargs['json']
    assert data['document_hash'] == "first_hash_789"
    assert data['previous_hash'] is None
