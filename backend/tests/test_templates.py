"""
Test Suite for Merkle Tree and Template Engine
==============================================
Tests for multi-page PDF tamper localization and W3C VC generation.
"""

import pytest
import os
import json
import hashlib
from datetime import datetime

from backend.services.templates import (
    MerkleTree, MerkleProof, MerkleTreeError,
    W3CVerifiableCredential, TemplateEngine,
    DocumentType, DocumentMetadata, PageHash
)


class TestMerkleTree:
    """Tests for Merkle Tree implementation."""
    
    def test_empty_tree(self):
        """Test Merkle tree with no hashes."""
        tree = MerkleTree([])
        assert tree.root_hash is None
    
    def test_single_page_tree(self):
        """Test Merkle tree with single page."""
        hashes = ["abc123"]
        tree = MerkleTree(hashes)
        
        assert tree.root_hash is not None
        assert tree.root_hash == "abc123"  # Single leaf is the root
    
    def test_two_page_tree(self):
        """Test Merkle tree with two pages."""
        hashes = ["hash1", "hash2"]
        tree = MerkleTree(hashes)
        
        expected = MerkleTree.hash_pair("hash1", "hash2")
        assert tree.root_hash == expected
    
    def test_four_page_tree(self):
        """Test Merkle tree with four pages (perfect binary tree)."""
        hashes = ["a", "b", "c", "d"]
        tree = MerkleTree(hashes)
        
        # Build expected tree manually
        ab = MerkleTree.hash_pair("a", "b")
        cd = MerkleTree.hash_pair("c", "d")
        root = MerkleTree.hash_pair(ab, cd)
        
        assert tree.root_hash == root
    
    def test_non_power_of_two_pages(self):
        """Test Merkle tree with non-power-of-two pages."""
        hashes = ["a", "b", "c"]  # 3 pages
        tree = MerkleTree(hashes)
        
        # Should pad to 4 and build tree
        assert tree.root_hash is not None
    
    def test_hash_pair_deterministic(self):
        """Test that hash_pair is deterministic."""
        result1 = MerkleTree.hash_pair("left", "right")
        result2 = MerkleTree.hash_pair("left", "right")
        
        assert result1 == result2
    
    def test_hash_pair_order_matters(self):
        """Test that hash_pair is order-sensitive."""
        result1 = MerkleTree.hash_pair("a", "b")
        result2 = MerkleTree.hash_pair("b", "a")
        
        assert result1 != result2


class TestMerkleProof:
    """Tests for Merkle proof generation and verification."""
    
    def test_generate_proof_single_page(self):
        """Test proof generation for single page document."""
        hashes = ["only_page"]
        tree = MerkleTree(hashes)
        
        proof = tree.get_proof(0)
        
        assert proof.page_number == 1
        assert proof.page_hash == "only_page"
        assert proof.root_hash == tree.root_hash
    
    def test_generate_proof_multi_page(self):
        """Test proof generation for multi-page document."""
        hashes = ["a", "b", "c", "d"]
        tree = MerkleTree(hashes)
        
        proof = tree.get_proof(0)  # First page
        
        assert proof.page_number == 1
        assert proof.page_hash == "a"
        assert len(proof.proof_path) > 0
    
    def test_verify_valid_proof(self):
        """Test that valid proof verifies correctly."""
        hashes = ["page1", "page2", "page3", "page4"]
        tree = MerkleTree(hashes)
        
        for i in range(len(hashes)):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(proof)
    
    def test_verify_tampered_proof_fails(self):
        """Test that tampered proof fails verification."""
        hashes = ["page1", "page2"]
        tree = MerkleTree(hashes)
        
        proof = tree.get_proof(0)
        
        # Tamper with the page hash
        tampered_proof = MerkleProof(
            page_number=proof.page_number,
            page_hash="tampered_hash",
            proof_path=proof.proof_path,
            root_hash=proof.root_hash
        )
        
        assert not MerkleTree.verify_proof(tampered_proof)
    
    def test_proof_invalid_page_index(self):
        """Test proof generation with invalid page index."""
        hashes = ["a", "b"]
        tree = MerkleTree(hashes)
        
        with pytest.raises(MerkleTreeError):
            tree.get_proof(10)
        
        with pytest.raises(MerkleTreeError):
            tree.get_proof(-1)


class TestTamperDetection:
    """Tests for tamper detection functionality."""
    
    def test_find_tampered_pages_none(self):
        """Test detection when no pages tampered."""
        original = ["a", "b", "c"]
        tree = MerkleTree(original)
        
        tampered = tree.find_tampered_pages(original)
        assert tampered == []
    
    def test_find_tampered_pages_single(self):
        """Test detection of single tampered page."""
        original = ["a", "b", "c"]
        tree = MerkleTree(["a", "TAMPERED", "c"])
        
        tampered = tree.find_tampered_pages(original)
        assert tampered == [2]  # 1-indexed
    
    def test_find_tampered_pages_multiple(self):
        """Test detection of multiple tampered pages."""
        original = ["a", "b", "c", "d"]
        tree = MerkleTree(["X", "b", "Y", "d"])
        
        tampered = tree.find_tampered_pages(original)
        assert set(tampered) == {1, 3}


class TestW3CVerifiableCredential:
    """Tests for W3C Verifiable Credentials generation."""
    
    def test_create_academic_credential_basic(self):
        """Test basic academic credential creation."""
        cred = W3CVerifiableCredential.create_academic_credential(
            credential_id="test-123",
            issuer_id="did:example:university",
            issuer_name="Test University",
            subject_id="did:example:student",
            subject_name="John Doe",
            degree="Bachelor of Science",
            major="Computer Science",
            graduation_date="2026-05-15"
        )
        
        # Check structure
        assert "@context" in cred
        assert "type" in cred
        assert "issuer" in cred
        assert "credentialSubject" in cred
        
        # Check values
        assert "VerifiableCredential" in cred["type"]
        assert "AcademicCredential" in cred["type"]
        assert cred["issuer"]["name"] == "Test University"
        assert cred["credentialSubject"]["degree"] == "Bachelor of Science"
    
    def test_create_academic_credential_with_signature(self):
        """Test academic credential with cryptographic proof."""
        cred = W3CVerifiableCredential.create_academic_credential(
            credential_id="test-456",
            issuer_id="did:example:university",
            issuer_name="Test University",
            subject_id="did:example:student",
            subject_name="Jane Doe",
            degree="Master of Arts",
            major="Philosophy",
            graduation_date="2026-12-15",
            document_hash="abc123hash",
            signature="base64signature=="
        )
        
        assert "proof" in cred
        assert cred["proof"]["type"] == "Ed25519Signature2020"
        assert cred["proof"]["proofValue"] == "base64signature=="
        assert cred["proof"]["documentHash"] == "abc123hash"
    
    def test_create_academic_credential_with_gpa(self):
        """Test academic credential with optional GPA."""
        cred = W3CVerifiableCredential.create_academic_credential(
            credential_id="test-789",
            issuer_id="did:example:university",
            issuer_name="Test University",
            subject_id="did:example:student",
            subject_name="Bob Smith",
            degree="Bachelor of Arts",
            major="Economics",
            graduation_date="2026-05-15",
            gpa=3.85
        )
        
        assert cred["credentialSubject"]["gpa"] == 3.85
    
    def test_create_aadhaar_credential(self):
        """Test Aadhaar credential creation."""
        cred = W3CVerifiableCredential.create_aadhaar_credential(
            credential_id="aadhaar-123",
            issuer_id="did:uidai:issuer",
            masked_aadhaar="XXXX-XXXX-1234",
            name="Test Person",
            dob="01-01-1990",
            gender="M",
            address={"state": "Maharashtra", "city": "Mumbai"}
        )
        
        # Check structure
        assert "@context" in cred
        assert "AadhaarCredential" in cred["type"]
        assert cred["credentialSubject"]["maskedAadhaar"] == "XXXX-XXXX-1234"
        assert cred["credentialSubject"]["gender"] == "M"
    
    def test_credential_context_is_valid(self):
        """Test that W3C VC context URLs are correct."""
        assert W3CVerifiableCredential.CONTEXT_VC_V2 == "https://www.w3.org/ns/credentials/v2"


class TestTemplateEngine:
    """Tests for the template engine."""
    
    def test_generate_generic_credential(self):
        """Test generating a generic credential."""
        engine = TemplateEngine()
        
        cred = engine.generate_credential(
            template_type=DocumentType.GENERIC,
            institution_id="inst-123",
            institution_name="Test Institution",
            credential_data={"field1": "value1"},
            signature="test_signature"
        )
        
        assert "@context" in cred
        assert cred["issuer"]["id"] == "did:certitrust:inst-123"
    
    def test_generate_academic_credential(self):
        """Test generating academic credential through template engine."""
        engine = TemplateEngine()
        
        cred = engine.generate_credential(
            template_type=DocumentType.ACADEMIC,
            institution_id="univ-456",
            institution_name="State University",
            credential_data={
                "subject_id": "student-789",
                "subject_name": "Alice",
                "degree": "PhD",
                "major": "Physics",
                "graduation_date": "2026-08-01"
            },
            document_hash="hash123",
            signature="sig456"
        )
        
        assert "AcademicCredential" in cred["type"]
    
    def test_build_qr_payload(self):
        """Test QR payload generation for W3C compliance."""
        engine = TemplateEngine()
        
        payload = engine.build_qr_payload(
            document_id="doc-123",
            document_hash="hash456",
            institution_id="inst-789",
            signature="signature_base64",
            merkle_root="merkle_root_hash"
        )
        
        assert payload["@context"] == "https://www.w3.org/ns/credentials/v2"
        assert payload["type"] == "VerifiablePresentation"
        assert payload["verificationData"]["documentHash"] == "hash456"
        assert payload["verificationData"]["merkleRoot"] == "merkle_root_hash"


class TestDocumentMetadata:
    """Tests for DocumentMetadata dataclass."""
    
    def test_create_metadata(self):
        """Test creating document metadata."""
        metadata = DocumentMetadata(
            document_id="doc-123",
            institution_id="inst-456",
            document_type=DocumentType.ACADEMIC
        )
        
        assert metadata.document_id == "doc-123"
        assert metadata.institution_id == "inst-456"
        assert metadata.issued_at is not None
    
    def test_metadata_with_page_hashes(self):
        """Test metadata with page hash list."""
        page_hashes = [
            PageHash(page_number=1, hash="hash1"),
            PageHash(page_number=2, hash="hash2")
        ]
        
        metadata = DocumentMetadata(
            document_id="doc-789",
            institution_id="inst-000",
            document_type=DocumentType.GENERIC,
            page_hashes=page_hashes
        )
        
        assert len(metadata.page_hashes) == 2
        assert metadata.page_hashes[0].hash == "hash1"
