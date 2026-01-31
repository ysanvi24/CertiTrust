import os
import pytest
from unittest.mock import patch, MagicMock
import sys

# Ensure backend is in path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# We will import log_audit_event from backend.main
# Since it doesn't exist yet, we will wrap the import in the test or assume it will exist when running
from main import log_audit_event

@patch("main.httpx.post")
def test_log_audit_event(mock_post):
    # Setup
    doc_hash = "1234567890abcdef"
    # Mock environment variables
    with patch.dict(os.environ, {
        "SUPABASE_URL": "https://example.supabase.co",
        "SUPABASE_SERVICE_ROLE_KEY": "fake-key"
    }):
        # Act
        log_audit_event(doc_hash)

        # Assert
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args

        assert args[0] == "https://example.supabase.co/rest/v1/audit_logs"
        assert kwargs["headers"]["apikey"] == "fake-key"
        assert kwargs["headers"]["Authorization"] == "Bearer fake-key"
        # We check that the payload contains the hash.
        # We might add timestamp, so we check subset or exact match depending on implementation.
        # For now, assuming just hash is strictly required by the prompt "log every issued document hash".
        assert kwargs["json"]["document_hash"] == doc_hash
