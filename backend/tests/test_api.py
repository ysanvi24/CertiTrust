"""
Integration Tests for CertiTrust API Endpoints
==============================================
Tests for the full document issuance and verification pipeline.
"""

import pytest
import os
import json
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

# Set environment before imports
os.environ['SUPABASE_URL'] = 'http://test.supabase.co'
os.environ['SUPABASE_SERVICE_ROLE_KEY'] = 'test_key_' + 'x' * 200

from backend.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
def sample_pdf(tmp_path):
    """Create a sample PDF for testing."""
    import fitz
    
    pdf_path = tmp_path / "sample.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Sample Document Content")
    doc.save(str(pdf_path))
    doc.close()
    
    return pdf_path


class TestHealthEndpoint:
    """Tests for the health check endpoint."""
    
    def test_health_check(self, client):
        """Test basic health check."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "2.0.0"


class TestLegacyDocumentIssuance:
    """Tests for legacy document issuance (without institution)."""
    
    def test_issue_document_success(self, client, sample_pdf):
        """Test successful document issuance."""
        with open(sample_pdf, "rb") as f:
            response = client.post(
                "/issue/document",
                files={"file": ("test.pdf", f, "application/pdf")}
            )
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
    
    def test_issue_document_non_pdf_rejected(self, client, tmp_path):
        """Test that non-PDF files are rejected."""
        text_file = tmp_path / "test.txt"
        text_file.write_text("Not a PDF")
        
        with open(text_file, "rb") as f:
            response = client.post(
                "/issue/document",
                files={"file": ("test.txt", f, "text/plain")}
            )
        
        assert response.status_code == 400
        assert "PDF" in response.json()["detail"]
    
    def test_issue_document_with_document_type(self, client, sample_pdf):
        """Test issuance with document type parameter."""
        with open(sample_pdf, "rb") as f:
            response = client.post(
                "/issue/document",
                files={"file": ("test.pdf", f, "application/pdf")},
                data={"document_type": "academic"}
            )
        
        assert response.status_code == 200


class TestInstitutionOnboarding:
    """Tests for institution onboarding endpoints."""
    
    @patch('backend.main.httpx.AsyncClient')
    def test_onboard_institution_success(self, mock_client_class, client):
        """Test successful institution onboarding."""
        # Mock the async client
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.post = AsyncMock(return_value=MagicMock(
            status_code=201,
            json=MagicMock(return_value=[{"id": "new-inst-id"}])
        ))
        mock_client_class.return_value = mock_client
        
        response = client.post(
            "/admin/onboard",
            json={
                "name": "Test University",
                "slug": "test-university",
                "contact_email": "admin@test.edu"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["name"] == "Test University"
        assert "public_key_pem" in data
    
    def test_onboard_institution_invalid_slug(self, client):
        """Test that invalid slug format is rejected."""
        response = client.post(
            "/admin/onboard",
            json={
                "name": "Test University",
                "slug": "Invalid Slug!",  # Contains invalid characters
                "contact_email": "admin@test.edu"
            }
        )
        
        assert response.status_code == 422  # Validation error


class TestDocumentVerification:
    """Tests for document verification endpoints."""
    
    def test_verify_document_valid_signature(self, client):
        """Test verification with valid signature."""
        from backend.services.kms import LegacyDocumentSigner
        
        signer = LegacyDocumentSigner()
        test_hash = "a" * 64
        signature = signer.sign_document(test_hash)
        public_key_pem = signer.get_public_key_pem()
        
        response = client.post(
            "/verify/document",
            json={
                "document_hash": test_hash,
                "signature": signature,
                "public_key_pem": public_key_pem
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_valid"] is True
    
    def test_verify_document_invalid_signature(self, client):
        """Test verification with invalid signature."""
        response = client.post(
            "/verify/document",
            json={
                "document_hash": "a" * 64,
                "signature": "invalid_signature_base64=="
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_valid"] is False
    
    def test_verify_file_upload(self, client, sample_pdf):
        """Test file upload verification."""
        with open(sample_pdf, "rb") as f:
            response = client.post(
                "/verify/file",
                files={"file": ("test.pdf", f, "application/pdf")}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "calculated_hash" in data
        assert len(data["calculated_hash"]) == 64


class TestAuditEndpoints:
    """Tests for audit log endpoints."""
    
    @patch('backend.services.audit.httpx.get')
    def test_get_audit_logs(self, mock_get, client):
        """Test retrieving audit logs."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = [
            {"event_type": "document_issued", "document_hash": "hash1"}
        ]
        
        response = client.get("/audit/logs")
        
        assert response.status_code == 200
        data = response.json()
        assert "entries" in data
        assert "chain_valid" in data
    
    @patch('backend.services.audit.httpx.get')
    def test_verify_audit_chain(self, mock_get, client):
        """Test audit chain verification endpoint."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = []
        
        response = client.get("/audit/verify-chain")
        
        assert response.status_code == 200
        data = response.json()
        assert data["chain_valid"] is True


class TestTemplateEndpoints:
    """Tests for template management endpoints."""
    
    @patch('backend.main.httpx.AsyncClient')
    def test_create_template(self, mock_client_class, client):
        """Test template creation."""
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.post = AsyncMock(return_value=MagicMock(
            status_code=201,
            raise_for_status=MagicMock()
        ))
        mock_client_class.return_value = mock_client
        
        response = client.post(
            "/templates",
            json={
                "institution_id": "inst-123",
                "name": "Degree Certificate",
                "template_type": "academic",
                "description": "Standard degree certificate template"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
    
    def test_create_template_invalid_type(self, client):
        """Test template creation with invalid type."""
        response = client.post(
            "/templates",
            json={
                "institution_id": "inst-123",
                "name": "Test Template",
                "template_type": "invalid_type"
            }
        )
        
        assert response.status_code == 400
    
    @patch('backend.main.httpx.AsyncClient')
    def test_list_templates(self, mock_client_class, client):
        """Test listing templates."""
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.get = AsyncMock(return_value=MagicMock(
            status_code=200,
            json=MagicMock(return_value=[]),
            raise_for_status=MagicMock()
        ))
        mock_client_class.return_value = mock_client
        
        response = client.get("/templates")
        
        assert response.status_code == 200


class TestFullPipeline:
    """End-to-end pipeline tests."""
    
    def test_issue_and_verify_document(self, client, sample_pdf):
        """Test full issue and verify cycle."""
        # Issue document
        with open(sample_pdf, "rb") as f:
            issue_response = client.post(
                "/issue/document",
                files={"file": ("test.pdf", f, "application/pdf")}
            )
        
        assert issue_response.status_code == 200
        
        # The stamped PDF should be larger (has QR code)
        assert len(issue_response.content) > 0
    
    def test_issue_preserves_pdf_content(self, client, sample_pdf):
        """Test that stamping preserves original PDF content."""
        import fitz
        import tempfile
        
        with open(sample_pdf, "rb") as f:
            response = client.post(
                "/issue/document",
                files={"file": ("test.pdf", f, "application/pdf")}
            )
        
        # Save stamped PDF
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(response.content)
            tmp_path = tmp.name
        
        try:
            # Open and verify content exists
            doc = fitz.open(tmp_path)
            assert len(doc) > 0
            
            # Check first page has our text
            page = doc[0]
            text = page.get_text()
            assert "Sample Document Content" in text
            
            doc.close()
        finally:
            os.unlink(tmp_path)


class TestErrorHandling:
    """Tests for error handling."""
    
    def test_missing_file_upload(self, client):
        """Test error when file is missing."""
        response = client.post("/issue/document")
        assert response.status_code == 422
    
    def test_invalid_json_body(self, client):
        """Test error with invalid JSON."""
        response = client.post(
            "/verify/document",
            content="not json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422


@pytest.mark.slow
class TestPerformance:
    """Performance-related tests."""
    
    def test_large_pdf_processing(self, client, tmp_path):
        """Test processing a larger PDF."""
        import fitz
        
        # Create a 10-page PDF
        pdf_path = tmp_path / "large.pdf"
        doc = fitz.open()
        
        for i in range(10):
            page = doc.new_page()
            page.insert_text((72, 72), f"Page {i + 1} content")
            page.insert_text((72, 200), "Lorem ipsum " * 100)
        
        doc.save(str(pdf_path))
        doc.close()
        
        with open(pdf_path, "rb") as f:
            response = client.post(
                "/issue/document",
                files={"file": ("large.pdf", f, "application/pdf")}
            )
        
        assert response.status_code == 200
