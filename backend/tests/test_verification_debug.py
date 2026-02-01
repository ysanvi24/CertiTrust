"""
Verification Debug Tests for CertiTrust
=======================================
TDD-based tests for the complete verification pipeline.

Test Cases:
1. Issue PDF → Extract QR → Verify payload matches
2. Tamper with PDF → Verify signature mismatch
3. Multi-page PDF → Verify Merkle root
4. Institution lookup → Verify public key retrieval
5. Edge cases: corrupted QR, missing fields, etc.

Run with:
    pytest backend/tests/test_verification_debug.py -v
"""

import pytest
import os
import sys
import json
import base64
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add backend to path for imports
import sys
import os

# Ensure backend parent directory is in path for consistent imports
backend_dir = os.path.dirname(os.path.dirname(__file__))
backend_parent = os.path.dirname(backend_dir)
if backend_parent not in sys.path:
    sys.path.insert(0, backend_parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Import using backend.* to be consistent with test_api.py
from backend.utils import secure_hash, hash_string
from backend.services.kms import KMSService, LegacyDocumentSigner
from backend.services.scanner import (
    PDFQRScanner, QRPayload, CleanDocumentHasher,
    verify_document_signature, scan_and_verify,
    VerificationErrorCode, QRNotFoundError, InvalidPayloadError
)
from backend.qr_service import (
    generate_qr, generate_w3c_qr_payload, stamp_document, QRConfig
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def verification_temp_pdf():
    """Creates a minimal valid PDF for testing verification."""
    import fitz
    
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((100, 100), "Test Document Content")
        page.insert_text((100, 150), "This is a test certificate.")
        doc.save(f.name)
        doc.close()
        yield f.name
    
    # Cleanup
    try:
        os.unlink(f.name)
    except:
        pass


@pytest.fixture
def multi_page_pdf():
    """Creates a multi-page PDF for Merkle tree testing."""
    import fitz
    
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        doc = fitz.open()
        
        for i in range(5):
            page = doc.new_page()
            page.insert_text((100, 100), f"Page {i + 1} Content")
            page.insert_text((100, 150), f"This is page {i + 1} of the document.")
        
        doc.save(f.name)
        doc.close()
        yield f.name
    
    try:
        os.unlink(f.name)
    except:
        pass


@pytest.fixture
def legacy_signer():
    """Creates a legacy document signer."""
    return LegacyDocumentSigner()


@pytest.fixture
def stamped_pdf(verification_temp_pdf, legacy_signer):
    """Creates a stamped PDF with QR code."""
    # Calculate hash
    doc_hash = secure_hash(verification_temp_pdf)
    
    # Sign
    signature = legacy_signer.sign_document(doc_hash)
    
    # Generate QR payload
    payload = generate_w3c_qr_payload(
        document_id="test-doc-001",
        document_hash=doc_hash,
        issuer_id="legacy",
        signature=signature,
        merkle_root=doc_hash,  # Simplified for single page
        credential_type="generic"
    )
    
    # Generate QR image
    qr_img = generate_qr(payload)
    
    # Stamp document
    output_path = verification_temp_pdf.replace(".pdf", "_stamped.pdf")
    stamp_document(verification_temp_pdf, output_path, qr_img)
    
    yield output_path, doc_hash, signature, payload
    
    try:
        os.unlink(output_path)
    except:
        pass


# ============================================================
# Test Case 1: Issue → Extract → Verify Payload Match
# ============================================================

class TestQRExtractionPipeline:
    """Tests for QR extraction from stamped PDFs."""
    
    def test_extract_qr_from_stamped_pdf(self, stamped_pdf):
        """Test that QR can be extracted from stamped PDF."""
        output_path, doc_hash, signature, original_payload = stamped_pdf
        
        scanner = PDFQRScanner(dpi=300)
        extracted_data = scanner.extract_qr_from_page(output_path, page_num=0)
        
        assert extracted_data is not None, "QR extraction failed"
        assert "proof" in extracted_data, "Missing proof in QR data"
        assert extracted_data["proof"]["documentHash"] == doc_hash, "Hash mismatch"
    
    def test_payload_parse_w3c_format(self, stamped_pdf):
        """Test W3C VC payload parsing."""
        output_path, doc_hash, signature, original_payload = stamped_pdf
        
        scanner = PDFQRScanner()
        extracted_data = scanner.extract_qr_from_page(output_path, page_num=0)
        
        payload = QRPayload.from_w3c_vc(extracted_data)
        
        assert payload.document_hash == doc_hash
        assert payload.signature == signature
        assert payload.issuer_id == "legacy"
    
    def test_signature_matches_after_extraction(self, stamped_pdf, legacy_signer):
        """Test that extracted signature can be verified."""
        output_path, doc_hash, signature, original_payload = stamped_pdf
        
        scanner = PDFQRScanner()
        extracted_data = scanner.extract_qr_from_page(output_path, page_num=0)
        payload = QRPayload.parse(extracted_data)
        
        # Verify signature using legacy signer
        is_valid = legacy_signer.verify_signature(
            payload.document_hash,
            payload.signature
        )
        
        assert is_valid, "Signature verification failed after extraction"
    
    def test_qr_payload_not_truncated(self, stamped_pdf):
        """Verify QR payload is not truncated (complete base64 signature)."""
        output_path, doc_hash, signature, original_payload = stamped_pdf
        
        scanner = PDFQRScanner()
        extracted_data = scanner.extract_qr_from_page(output_path, page_num=0)
        
        extracted_sig = extracted_data["proof"]["proofValue"]
        
        # Ed25519 signature is 64 bytes = 88 base64 chars (with padding)
        assert len(extracted_sig) >= 64, f"Signature appears truncated: {len(extracted_sig)} chars"
        
        # Verify it's valid base64
        try:
            decoded = base64.b64decode(extracted_sig)
            assert len(decoded) == 64, f"Signature wrong length after decode: {len(decoded)}"
        except Exception as e:
            pytest.fail(f"Signature is not valid base64: {e}")


# ============================================================
# Test Case 2: Tamper Detection
# ============================================================

class TestTamperDetection:
    """Tests for detecting document tampering."""
    
    def test_tampered_pdf_fails_verification(self, stamped_pdf, legacy_signer):
        """Test that modifying PDF text causes signature mismatch."""
        import fitz
        
        output_path, original_hash, signature, payload = stamped_pdf
        
        # Tamper with the document
        doc = fitz.open(output_path)
        page = doc[0]
        
        # Add some text (simulating tampering)
        page.insert_text((200, 200), "TAMPERED!")
        
        tampered_path = output_path.replace("_stamped.pdf", "_tampered.pdf")
        doc.save(tampered_path)
        doc.close()
        
        try:
            # Calculate new hash
            tampered_hash = secure_hash(tampered_path)
            
            # Hashes should be different
            assert tampered_hash != original_hash, "Tampered hash should differ"
            
            # Signature verification against tampered hash should fail
            is_valid = legacy_signer.verify_signature(tampered_hash, signature)
            assert not is_valid, "Tampered document should fail verification"
            
            # But original hash + signature should still work
            is_valid_original = legacy_signer.verify_signature(original_hash, signature)
            assert is_valid_original, "Original hash should still verify"
            
        finally:
            try:
                os.unlink(tampered_path)
            except:
                pass
    
    def test_single_byte_metadata_change_fails_verification(self, stamped_pdf, legacy_signer):
        """
        NEGATIVE TEST: Verify that changing a single byte in PDF metadata 
        causes verification to fail.
        
        This tests the cryptographic integrity guarantee - even the smallest
        change must be detected.
        """
        import fitz
        
        output_path, original_hash, signature, payload = stamped_pdf
        
        # Read original file bytes
        with open(output_path, 'rb') as f:
            original_bytes = bytearray(f.read())
        
        # Find a text content location (after the PDF header)
        # Look for the text we inserted
        text_marker = b"Test Document"
        marker_pos = original_bytes.find(text_marker)
        
        if marker_pos == -1:
            # If exact text not found, just flip a byte in the middle
            marker_pos = len(original_bytes) // 2
        
        # Create tampered version with single byte flip
        tampered_bytes = original_bytes.copy()
        original_byte = tampered_bytes[marker_pos]
        tampered_bytes[marker_pos] = (original_byte + 1) % 256  # Flip single byte
        
        tampered_path = output_path.replace("_stamped.pdf", "_singlebyte_tampered.pdf")
        
        try:
            # Write tampered file
            with open(tampered_path, 'wb') as f:
                f.write(tampered_bytes)
            
            # Calculate hash of tampered file
            tampered_hash = secure_hash(tampered_path)
            
            # CRITICAL: Hash MUST be different even for single byte change
            assert tampered_hash != original_hash, (
                "SECURITY FAILURE: Single byte change did not alter hash! "
                f"Original: {original_hash[:16]}... Tampered: {tampered_hash[:16]}..."
            )
            
            # Signature verification must fail
            is_valid = legacy_signer.verify_signature(tampered_hash, signature)
            assert not is_valid, (
                "SECURITY FAILURE: Single byte tampered document passed verification!"
            )
            
            # Verify the original still works (sanity check)
            is_valid_original = legacy_signer.verify_signature(original_hash, signature)
            assert is_valid_original, "Original signature should still verify"
            
        finally:
            try:
                os.unlink(tampered_path)
            except:
                pass
    
    def test_metadata_title_tampering_detected(self, stamped_pdf, legacy_signer):
        """
        Test that changing PDF metadata (title, author) is detected.
        
        Some attackers might try to change only metadata thinking it won't
        affect the cryptographic hash.
        """
        import fitz
        
        output_path, original_hash, signature, payload = stamped_pdf
        
        # Open and modify metadata
        doc = fitz.open(output_path)
        
        # Change metadata
        doc.set_metadata({
            "title": "FORGED CERTIFICATE",
            "author": "Malicious Actor",
            "subject": "This document has been tampered"
        })
        
        tampered_path = output_path.replace("_stamped.pdf", "_metadata_tampered.pdf")
        doc.save(tampered_path)
        doc.close()
        
        try:
            # Calculate new hash
            tampered_hash = secure_hash(tampered_path)
            
            # Hash should be different (metadata is part of PDF)
            assert tampered_hash != original_hash, (
                "Metadata-only change should still alter hash"
            )
            
            # Verification should fail
            is_valid = legacy_signer.verify_signature(tampered_hash, signature)
            assert not is_valid, "Metadata-tampered document should fail verification"
            
        finally:
            try:
                os.unlink(tampered_path)
            except:
                pass
    
    def test_qr_hash_vs_file_hash_explanation(self, stamped_pdf):
        """
        Test that we understand the hash discrepancy correctly.
        
        CRITICAL: The stamped PDF will have a DIFFERENT hash than
        what's stored in the QR code. This is because:
        1. Original PDF is hashed → hash_A
        2. hash_A is signed → signature
        3. QR with hash_A + signature is added to PDF
        4. Stamped PDF now has hash_B ≠ hash_A
        
        This is EXPECTED behavior. We verify signature against hash_A (from QR).
        """
        output_path, original_hash, signature, payload = stamped_pdf
        
        # Hash the stamped file
        stamped_file_hash = secure_hash(output_path)
        
        # Extract QR
        scanner = PDFQRScanner()
        qr_data = scanner.extract_qr_from_page(output_path, page_num=0)
        qr_hash = qr_data["proof"]["documentHash"]
        
        # These should be different!
        assert stamped_file_hash != qr_hash, (
            "Stamped file hash should differ from QR hash. "
            "The QR contains the ORIGINAL document hash."
        )
        
        # QR hash should match original
        assert qr_hash == original_hash, "QR should contain original hash"


# ============================================================
# Test Case 3: Multi-Page Merkle Tree
# ============================================================

class TestMerkleTreeVerification:
    """Tests for multi-page PDF Merkle tree verification."""
    
    def test_multipage_merkle_root_in_qr(self, multi_page_pdf, legacy_signer):
        """Test that multi-page PDFs have Merkle root in QR."""
        from services.templates import MerkleTree, extract_page_hashes_from_pdf
        
        # Calculate page hashes
        page_hashes = list(extract_page_hashes_from_pdf(multi_page_pdf))
        hash_values = [ph.hash for ph in page_hashes]
        
        # Build Merkle tree
        merkle = MerkleTree(hash_values)
        merkle_root = merkle.root_hash
        
        # Sign
        doc_hash = secure_hash(multi_page_pdf)
        signature = legacy_signer.sign_document(doc_hash)
        
        # Generate QR with Merkle root
        payload = generate_w3c_qr_payload(
            document_id="multi-page-doc",
            document_hash=doc_hash,
            issuer_id="legacy",
            signature=signature,
            merkle_root=merkle_root,
            credential_type="academic"
        )
        
        qr_img = generate_qr(payload)
        
        output_path = multi_page_pdf.replace(".pdf", "_stamped.pdf")
        stamp_document(multi_page_pdf, output_path, qr_img)
        
        try:
            # Extract and verify
            scanner = PDFQRScanner()
            extracted = scanner.extract_qr_from_page(output_path)
            
            assert extracted is not None
            assert "proof" in extracted
            assert extracted["proof"].get("merkleRoot") == merkle_root
            
        finally:
            try:
                os.unlink(output_path)
            except:
                pass


# ============================================================
# Test Case 4: Scanner Robustness
# ============================================================

class TestScannerRobustness:
    """Tests for scanner edge cases and error handling."""
    
    def test_no_qr_returns_none(self, verification_temp_pdf):
        """Test that PDF without QR returns None."""
        scanner = PDFQRScanner()
        result = scanner.extract_qr_from_page(verification_temp_pdf)
        
        assert result is None, "Should return None for PDF without QR"
    
    def test_scan_all_pages_finds_qr(self, stamped_pdf):
        """Test scanning all pages finds the QR."""
        output_path, _, _, _ = stamped_pdf
        
        scanner = PDFQRScanner()
        result, page_num = scanner.scan_all_pages(output_path)
        
        assert result is not None
        assert page_num == 0  # QR should be on first page
    
    def test_high_dpi_improves_detection(self, stamped_pdf):
        """Test that higher DPI improves QR detection."""
        output_path, _, _, _ = stamped_pdf
        
        # Test at different DPIs
        for dpi in [100, 150, 300]:
            scanner = PDFQRScanner(dpi=dpi)
            result = scanner.extract_qr_from_page(output_path)
            
            # Should work at all reasonable DPIs
            if dpi >= 150:
                assert result is not None, f"Failed at DPI {dpi}"
    
    def test_invalid_page_raises_error(self, stamped_pdf):
        """Test that invalid page number raises error."""
        output_path, _, _, _ = stamped_pdf
        
        scanner = PDFQRScanner()
        
        with pytest.raises(Exception):
            scanner.extract_qr_from_page(output_path, page_num=999)


# ============================================================
# Test Case 5: Payload Parsing
# ============================================================

class TestPayloadParsing:
    """Tests for QR payload parsing."""
    
    def test_parse_w3c_vc_payload(self):
        """Test parsing W3C VC format payload."""
        data = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": ["VerifiablePresentation", "academic"],
            "id": "urn:certitrust:doc-123",
            "holder": "did:certitrust:inst-456",
            "proof": {
                "type": "Ed25519Signature2020",
                "verificationMethod": "did:certitrust:inst-456#key-1",
                "proofValue": "dGVzdHNpZ25hdHVyZQ==",
                "documentHash": "abc123hash",
                "merkleRoot": "merkle123"
            }
        }
        
        payload = QRPayload.parse(data)
        
        assert payload.document_id == "doc-123"
        assert payload.issuer_id == "inst-456"
        assert payload.document_hash == "abc123hash"
        assert payload.signature == "dGVzdHNpZ25hdHVyZQ=="
        assert payload.merkle_root == "merkle123"
        assert payload.credential_type == "academic"
    
    def test_parse_simple_payload(self):
        """Test parsing simple format payload."""
        data = {
            "id": "simple-doc",
            "hash": "simplehash123",
            "sig": "simplesig==",
            "issuer": "simple-issuer"
        }
        
        payload = QRPayload.parse(data)
        
        assert payload.document_id == "simple-doc"
        assert payload.document_hash == "simplehash123"
        assert payload.signature == "simplesig=="
        assert payload.issuer_id == "simple-issuer"
    
    def test_missing_required_fields_raises_error(self):
        """Test that missing required fields raises error."""
        invalid_data = {
            "id": "doc-123"
            # Missing hash and sig
        }
        
        with pytest.raises(InvalidPayloadError):
            QRPayload.parse(invalid_data)


# ============================================================
# Test Case 6: Signature Verification Function
# ============================================================

class TestSignatureVerification:
    """Tests for the signature verification function."""
    
    def test_valid_signature_verifies(self, legacy_signer):
        """Test that valid signature verifies correctly."""
        doc_hash = "test_document_hash_12345"
        signature = legacy_signer.sign_document(doc_hash)
        public_key_pem = legacy_signer.get_public_key_pem()
        
        result = verify_document_signature(doc_hash, signature, public_key_pem)
        
        assert result is True
    
    def test_invalid_signature_fails(self, legacy_signer):
        """Test that invalid signature fails verification."""
        doc_hash = "test_document_hash_12345"
        wrong_signature = base64.b64encode(b"wrong" * 13).decode()  # 65 bytes
        public_key_pem = legacy_signer.get_public_key_pem()
        
        result = verify_document_signature(doc_hash, wrong_signature, public_key_pem)
        
        assert result is False
    
    def test_wrong_hash_fails(self, legacy_signer):
        """Test that wrong hash fails verification."""
        doc_hash = "original_hash"
        wrong_hash = "different_hash"
        signature = legacy_signer.sign_document(doc_hash)
        public_key_pem = legacy_signer.get_public_key_pem()
        
        result = verify_document_signature(wrong_hash, signature, public_key_pem)
        
        assert result is False
    
    def test_wrong_key_fails(self, legacy_signer):
        """Test that verification with wrong public key fails."""
        doc_hash = "test_document_hash"
        signature = legacy_signer.sign_document(doc_hash)
        
        # Generate a different key
        different_signer = LegacyDocumentSigner()
        # Force new key generation
        from cryptography.hazmat.primitives.asymmetric import ed25519
        different_private = ed25519.Ed25519PrivateKey.generate()
        different_public_pem = different_private.public_key().public_bytes(
            encoding=__import__('cryptography.hazmat.primitives.serialization', 
                              fromlist=['Encoding']).Encoding.PEM,
            format=__import__('cryptography.hazmat.primitives.serialization',
                            fromlist=['PublicFormat']).PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        result = verify_document_signature(doc_hash, signature, different_public_pem)
        
        assert result is False


# ============================================================
# Test Case 7: End-to-End Integration
# ============================================================

class TestEndToEndIntegration:
    """Full integration tests for the verification pipeline."""
    
    def test_complete_issue_verify_cycle(self, verification_temp_pdf, legacy_signer):
        """Test complete issue → stamp → verify cycle."""
        # 1. Hash original document
        original_hash = secure_hash(verification_temp_pdf)
        
        # 2. Sign
        signature = legacy_signer.sign_document(original_hash)
        
        # 3. Generate QR
        payload = generate_w3c_qr_payload(
            document_id="e2e-test",
            document_hash=original_hash,
            issuer_id="legacy",
            signature=signature
        )
        qr_img = generate_qr(payload)
        
        # 4. Stamp
        stamped_path = verification_temp_pdf.replace(".pdf", "_e2e_stamped.pdf")
        stamp_document(verification_temp_pdf, stamped_path, qr_img)
        
        try:
            # 5. Extract QR
            scanner = PDFQRScanner(dpi=300)
            extracted = scanner.extract_qr_from_page(stamped_path)
            
            assert extracted is not None
            
            # 6. Parse payload
            parsed = QRPayload.parse(extracted)
            
            assert parsed.document_hash == original_hash
            assert parsed.signature == signature
            
            # 7. Verify signature
            public_key = legacy_signer.get_public_key_pem()
            is_valid = verify_document_signature(
                parsed.document_hash,
                parsed.signature,
                public_key
            )
            
            assert is_valid, "End-to-end verification failed!"
            
        finally:
            try:
                os.unlink(stamped_path)
            except:
                pass
    
    def test_scan_and_verify_helper(self, stamped_pdf, legacy_signer):
        """Test the scan_and_verify helper function."""
        output_path, doc_hash, signature, _ = stamped_pdf
        
        def fetch_institution(issuer_id):
            if issuer_id == "legacy":
                return {
                    "id": "legacy",
                    "name": "Legacy Issuer",
                    "public_key_pem": legacy_signer.get_public_key_pem()
                }
            return None
        
        result = scan_and_verify(output_path, fetch_institution)
        
        assert result.success
        assert result.error_code == VerificationErrorCode.SUCCESS
        assert result.signature_valid is True
        assert result.payload.document_hash == doc_hash


# ============================================================
# Run Tests
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
