"""
Pytest Configuration and Fixtures for CertiTrust Backend Tests
==============================================================
"""

import pytest
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Set up test environment variables
os.environ.setdefault('SUPABASE_URL', 'http://test.supabase.co')
os.environ.setdefault('SUPABASE_SERVICE_ROLE_KEY', 'test_service_role_key_' + 'x' * 200)
os.environ.setdefault('ISSUER_PRIVATE_KEY', '')


@pytest.fixture
def temp_file(tmp_path):
    """Create a temporary text file for testing."""
    d = tmp_path / "subdir"
    d.mkdir()
    p = d / "test_file.txt"
    p.write_text("Hello World!")
    return p


@pytest.fixture
def temp_pdf(tmp_path):
    """Create a minimal test PDF file."""
    import fitz
    
    pdf_path = tmp_path / "test_document.pdf"
    doc = fitz.open()
    
    # Add 3 pages with different content
    for i in range(3):
        page = doc.new_page()
        page.insert_text((72, 72), f"Test Page {i + 1}")
        page.insert_text((72, 100), f"Content for page {i + 1}")
    
    doc.save(str(pdf_path))
    doc.close()
    
    return pdf_path


@pytest.fixture
def sample_document_hash():
    """Provide a sample document hash."""
    return "a" * 64  # Valid SHA-256 hash format


@pytest.fixture
def mock_supabase():
    """Mock Supabase client for testing."""
    mock = MagicMock()
    mock.table.return_value.select.return_value.execute.return_value.data = []
    return mock


@pytest.fixture
def sample_institution_data():
    """Provide sample institution data for testing."""
    return {
        "id": "test-institution-123",
        "name": "Test University",
        "slug": "test-university",
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----",
        "contact_email": "admin@test.edu",
        "domain": "test.edu",
        "is_active": True
    }


@pytest.fixture
def sample_academic_credential_data():
    """Provide sample academic credential data."""
    return {
        "subject_id": "did:example:student123",
        "subject_name": "John Doe",
        "degree": "Bachelor of Science",
        "major": "Computer Science",
        "graduation_date": "2026-05-15",
        "gpa": 3.75
    }


@pytest.fixture
def large_file(tmp_path):
    """Create a large file for memory testing."""
    large_file_path = tmp_path / "large_file.bin"
    
    # Create a 10MB file (safe for 8GB RAM testing)
    chunk_size = 1024 * 1024  # 1MB chunks
    total_size = 10 * chunk_size
    
    with open(large_file_path, 'wb') as f:
        written = 0
        while written < total_size:
            f.write(os.urandom(min(chunk_size, total_size - written)))
            written += chunk_size
    
    return large_file_path


@pytest.fixture
def temp_dir(tmp_path):
    """Provide a temporary directory for file operations."""
    test_dir = tmp_path / "certitrust_test"
    test_dir.mkdir()
    return test_dir


# Async test support
@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Test markers
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests requiring external services"
    )
    config.addinivalue_line(
        "markers", "memory: marks tests for memory-sensitive operations"
    )
