"""
Document Template Engine for CertiTrust
=======================================
Supports multiple document standards:
- Aadhaar: UIDAI Offline e-KYC JSON/XML format
- Academic: W3C Verifiable Credentials (VCDM v2.0)
- Permits: Government permit standards
- Generic: Custom document templates

Includes Merkle Tree hashing for multi-page PDF tamper localization.
Memory optimized for 8GB RAM environments.
"""

import os
import json
import hashlib
import math
from typing import Dict, Any, List, Optional, Tuple, Generator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import uuid


class DocumentType(Enum):
    """Supported document types."""
    AADHAAR = "aadhaar"
    ACADEMIC = "academic"
    PERMIT = "permit"
    GENERIC = "generic"
    W3C_VC = "w3c_vc"


@dataclass
class PageHash:
    """Hash data for a single document page."""
    page_number: int
    hash: str
    byte_range: Tuple[int, int] = (0, 0)


@dataclass
class MerkleNode:
    """Node in the Merkle tree."""
    hash: str
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None
    page_number: Optional[int] = None


@dataclass
class MerkleProof:
    """Proof of inclusion for a specific page."""
    page_number: int
    page_hash: str
    proof_path: List[Tuple[str, str]]  # List of (hash, direction) where direction is 'L' or 'R'
    root_hash: str


@dataclass
class DocumentMetadata:
    """Metadata container for issued documents."""
    document_id: str
    institution_id: str
    document_type: DocumentType
    subject_id: Optional[str] = None
    issued_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    merkle_root: Optional[str] = None
    page_hashes: List[PageHash] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)


class TemplateError(Exception):
    """Base exception for template operations."""
    pass


class MerkleTreeError(Exception):
    """Exception for Merkle tree operations."""
    pass


class MerkleTree:
    """
    Merkle Tree implementation for multi-page PDF tamper localization.
    
    Memory-efficient implementation using generators for large documents.
    Supports partial tree verification for detecting which page was tampered.
    """
    
    CHUNK_SIZE = 65536  # 64KB chunks for hashing
    
    def __init__(self, page_hashes: List[str] = None):
        """
        Initialize Merkle tree from page hashes.
        
        Args:
            page_hashes: List of SHA-256 hashes (one per page)
        """
        self._page_hashes = page_hashes or []
        self._root: Optional[MerkleNode] = None
        self._tree_levels: List[List[str]] = []
        
        if self._page_hashes:
            self._build_tree()
    
    @staticmethod
    def hash_data(data: bytes) -> str:
        """SHA-256 hash of bytes, returned as hex string."""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def hash_pair(left: str, right: str) -> str:
        """Hash two node hashes together."""
        combined = (left + right).encode('utf-8')
        return hashlib.sha256(combined).hexdigest()
    
    def _build_tree(self):
        """Builds the Merkle tree from leaf hashes."""
        if not self._page_hashes:
            return
        
        # Pad to power of 2 if necessary
        n = len(self._page_hashes)
        padded_size = 2 ** math.ceil(math.log2(max(n, 1)))
        
        # Create leaf level
        leaves = self._page_hashes.copy()
        
        # Pad with duplicate of last hash if needed
        while len(leaves) < padded_size:
            leaves.append(leaves[-1])
        
        self._tree_levels = [leaves]
        
        # Build tree bottom-up
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent_hash = self.hash_pair(left, right)
                next_level.append(parent_hash)
            self._tree_levels.append(next_level)
            current_level = next_level
        
        # Root is the only node at the top level
        self._root = MerkleNode(hash=current_level[0]) if current_level else None
    
    @property
    def root_hash(self) -> Optional[str]:
        """Returns the Merkle root hash."""
        return self._root.hash if self._root else None
    
    def get_proof(self, page_index: int) -> MerkleProof:
        """
        Generates a Merkle proof for a specific page.
        
        Args:
            page_index: Zero-based index of the page
            
        Returns:
            MerkleProof object containing the proof path
            
        Raises:
            MerkleTreeError: If page index is invalid
        """
        if page_index < 0 or page_index >= len(self._page_hashes):
            raise MerkleTreeError(f"Invalid page index: {page_index}")
        
        proof_path = []
        current_index = page_index
        
        # Pad index to match tree structure
        n = len(self._page_hashes)
        padded_size = 2 ** math.ceil(math.log2(max(n, 1)))
        
        if page_index >= padded_size:
            raise MerkleTreeError(f"Page index {page_index} exceeds tree size")
        
        # Walk up the tree, collecting sibling hashes
        for level_idx, level in enumerate(self._tree_levels[:-1]):
            # Determine sibling index
            if current_index % 2 == 0:
                # We are on the left, sibling is on the right
                sibling_index = current_index + 1
                direction = 'R'
            else:
                # We are on the right, sibling is on the left
                sibling_index = current_index - 1
                direction = 'L'
            
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
                proof_path.append((sibling_hash, direction))
            
            # Move to parent index
            current_index = current_index // 2
        
        return MerkleProof(
            page_number=page_index + 1,
            page_hash=self._page_hashes[page_index],
            proof_path=proof_path,
            root_hash=self.root_hash
        )
    
    @staticmethod
    def verify_proof(proof: MerkleProof) -> bool:
        """
        Verifies a Merkle proof.
        
        Args:
            proof: MerkleProof object to verify
            
        Returns:
            True if the proof is valid
        """
        current_hash = proof.page_hash
        
        for sibling_hash, direction in proof.proof_path:
            if direction == 'L':
                current_hash = MerkleTree.hash_pair(sibling_hash, current_hash)
            else:
                current_hash = MerkleTree.hash_pair(current_hash, sibling_hash)
        
        return current_hash == proof.root_hash
    
    def find_tampered_pages(self, original_hashes: List[str]) -> List[int]:
        """
        Identifies which pages have been tampered with.
        
        Args:
            original_hashes: List of original page hashes
            
        Returns:
            List of 1-indexed page numbers that differ
        """
        tampered = []
        for i, (original, current) in enumerate(zip(original_hashes, self._page_hashes)):
            if original != current:
                tampered.append(i + 1)
        return tampered


def extract_page_hashes_from_pdf(pdf_path: str) -> Generator[PageHash, None, None]:
    """
    Memory-efficient extraction of page hashes from a PDF.
    Uses PyMuPDF with chunked processing.
    
    Args:
        pdf_path: Path to the PDF file
        
    Yields:
        PageHash objects for each page
    """
    import fitz  # PyMuPDF
    
    doc = fitz.open(pdf_path)
    
    try:
        for page_num in range(len(doc)):
            page = doc[page_num]
            
            # Get page content as bytes (includes text, images, etc.)
            page_bytes = page.get_text("rawdict", flags=fitz.TEXT_PRESERVE_WHITESPACE)
            page_json = json.dumps(page_bytes, sort_keys=True).encode('utf-8')
            
            # Hash the page content
            page_hash = hashlib.sha256(page_json).hexdigest()
            
            yield PageHash(
                page_number=page_num + 1,
                hash=page_hash
            )
            
            # Clear page from memory
            del page_bytes, page_json
            
    finally:
        doc.close()


class W3CVerifiableCredential:
    """
    W3C Verifiable Credentials Data Model v2.0 implementation.
    
    Generates JSON-LD formatted credentials following W3C standards.
    Reference: https://www.w3.org/TR/vc-data-model-2.0/
    """
    
    # Standard W3C VC context URLs
    CONTEXT_VC_V2 = "https://www.w3.org/ns/credentials/v2"
    CONTEXT_EXAMPLES = "https://www.w3.org/ns/credentials/examples/v2"
    
    # Academic credential context (example)
    CONTEXT_ACADEMIC = {
        "@context": {
            "AcademicCredential": "https://certitrust.io/vocab#AcademicCredential",
            "degree": "https://certitrust.io/vocab#degree",
            "institution": "https://certitrust.io/vocab#institution",
            "major": "https://certitrust.io/vocab#major",
            "gpa": "https://certitrust.io/vocab#gpa",
            "graduationDate": "https://certitrust.io/vocab#graduationDate"
        }
    }
    
    @staticmethod
    def create_academic_credential(
        credential_id: str,
        issuer_id: str,
        issuer_name: str,
        subject_id: str,
        subject_name: str,
        degree: str,
        major: str,
        graduation_date: str,
        gpa: Optional[float] = None,
        issuance_date: Optional[str] = None,
        expiration_date: Optional[str] = None,
        document_hash: Optional[str] = None,
        signature: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates a W3C Verifiable Credential for academic credentials.
        
        Args:
            credential_id: Unique identifier for the credential
            issuer_id: DID or URI of the issuing institution
            issuer_name: Name of the issuing institution
            subject_id: DID or identifier of the credential subject
            subject_name: Name of the subject
            degree: Type of degree (e.g., "Bachelor of Science")
            major: Field of study
            graduation_date: Date of graduation (ISO format)
            gpa: Grade point average (optional)
            issuance_date: Date credential was issued
            expiration_date: Optional expiration date
            document_hash: SHA-256 hash of associated document
            signature: Ed25519 signature (base64)
            
        Returns:
            W3C VC compliant JSON-LD document
        """
        now = datetime.now(timezone.utc).isoformat()
        
        credential = {
            "@context": [
                W3CVerifiableCredential.CONTEXT_VC_V2,
                W3CVerifiableCredential.CONTEXT_ACADEMIC
            ],
            "id": f"urn:uuid:{credential_id}",
            "type": ["VerifiableCredential", "AcademicCredential"],
            "issuer": {
                "id": issuer_id,
                "name": issuer_name
            },
            "issuanceDate": issuance_date or now,
            "credentialSubject": {
                "id": subject_id,
                "name": subject_name,
                "degree": degree,
                "major": major,
                "graduationDate": graduation_date
            }
        }
        
        if gpa is not None:
            credential["credentialSubject"]["gpa"] = gpa
        
        if expiration_date:
            credential["expirationDate"] = expiration_date
        
        # Add cryptographic proof
        if document_hash and signature:
            credential["proof"] = {
                "type": "Ed25519Signature2020",
                "created": now,
                "verificationMethod": f"{issuer_id}#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": signature,
                "documentHash": document_hash
            }
        
        return credential
    
    @staticmethod
    def create_aadhaar_credential(
        credential_id: str,
        issuer_id: str,
        masked_aadhaar: str,  # Last 4 digits visible
        name: str,
        dob: str,
        gender: str,
        address: Dict[str, str],
        photo_hash: Optional[str] = None,
        signature: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates a UIDAI-compliant Aadhaar e-KYC credential.
        
        Follows Offline e-KYC XML 3.0 standard adapted to JSON-LD.
        
        Args:
            credential_id: Unique credential ID
            issuer_id: UIDAI issuer identifier
            masked_aadhaar: Masked Aadhaar number (XXXX-XXXX-1234)
            name: Name as per Aadhaar
            dob: Date of birth (DD-MM-YYYY)
            gender: Gender (M/F/O)
            address: Address components
            photo_hash: SHA-256 hash of photo (not the photo itself)
            signature: Ed25519 signature
            
        Returns:
            Aadhaar e-KYC compliant JSON document
        """
        now = datetime.now(timezone.utc).isoformat()
        
        credential = {
            "@context": [
                W3CVerifiableCredential.CONTEXT_VC_V2,
                {
                    "@context": {
                        "AadhaarCredential": "https://uidai.gov.in/vocab#AadhaarCredential",
                        "maskedAadhaar": "https://uidai.gov.in/vocab#maskedAadhaar",
                        "photoHash": "https://uidai.gov.in/vocab#photoHash"
                    }
                }
            ],
            "id": f"urn:uuid:{credential_id}",
            "type": ["VerifiableCredential", "AadhaarCredential"],
            "issuer": {
                "id": issuer_id,
                "name": "Unique Identification Authority of India"
            },
            "issuanceDate": now,
            "credentialSubject": {
                "maskedAadhaar": masked_aadhaar,
                "name": name,
                "dateOfBirth": dob,
                "gender": gender,
                "address": address
            }
        }
        
        if photo_hash:
            credential["credentialSubject"]["photoHash"] = photo_hash
        
        if signature:
            credential["proof"] = {
                "type": "Ed25519Signature2020",
                "created": now,
                "verificationMethod": f"{issuer_id}#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": signature
            }
        
        return credential


class TemplateEngine:
    """
    Dynamic document template engine.
    
    Manages document templates stored in Supabase and generates
    credentials based on template definitions.
    """
    
    def __init__(self, supabase_url: Optional[str] = None,
                 supabase_key: Optional[str] = None):
        """
        Initialize template engine with Supabase connection.
        
        Args:
            supabase_url: Supabase project URL
            supabase_key: Supabase service role key
        """
        self._supabase_url = supabase_url or os.getenv("SUPABASE_URL")
        self._supabase_key = supabase_key or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    
    def _get_headers(self) -> Dict[str, str]:
        """Returns Supabase API headers."""
        return {
            "apikey": self._supabase_key,
            "Authorization": f"Bearer {self._supabase_key}",
            "Content-Type": "application/json"
        }
    
    async def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetches a template from Supabase.
        
        Args:
            template_id: UUID of the template
            
        Returns:
            Template data or None if not found
        """
        import httpx
        
        url = f"{self._supabase_url}/rest/v1/document_templates"
        params = {"id": f"eq.{template_id}", "select": "*"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self._get_headers(), params=params)
            
            if response.status_code == 200:
                data = response.json()
                return data[0] if data else None
            return None
    
    async def create_template(
        self,
        institution_id: str,
        name: str,
        template_type: DocumentType,
        json_schema: Optional[Dict[str, Any]] = None,
        ld_context: Optional[Dict[str, Any]] = None,
        required_fields: Optional[List[str]] = None,
        description: Optional[str] = None
    ) -> str:
        """
        Creates a new document template.
        
        Args:
            institution_id: UUID of the owning institution
            name: Template name
            template_type: Type of document
            json_schema: JSON Schema for validation
            ld_context: JSON-LD context for W3C VC
            required_fields: List of required field names
            description: Template description
            
        Returns:
            UUID of created template
        """
        import httpx
        
        url = f"{self._supabase_url}/rest/v1/document_templates"
        
        data = {
            "institution_id": institution_id,
            "name": name,
            "template_type": template_type.value,
            "json_schema": json_schema,
            "ld_context": ld_context,
            "required_fields": required_fields or [],
            "description": description,
            "is_active": True
        }
        
        headers = self._get_headers()
        headers["Prefer"] = "return=representation"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=data)
            response.raise_for_status()
            result = response.json()
            return result[0]["id"]
    
    def generate_credential(
        self,
        template_type: DocumentType,
        institution_id: str,
        institution_name: str,
        credential_data: Dict[str, Any],
        document_hash: Optional[str] = None,
        signature: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generates a credential based on template type.
        
        Args:
            template_type: Type of credential to generate
            institution_id: Issuing institution ID
            institution_name: Name of issuing institution
            credential_data: Data to populate the credential
            document_hash: Optional document hash
            signature: Optional signature
            
        Returns:
            Generated credential document
        """
        credential_id = str(uuid.uuid4())
        
        if template_type == DocumentType.ACADEMIC or template_type == DocumentType.W3C_VC:
            return W3CVerifiableCredential.create_academic_credential(
                credential_id=credential_id,
                issuer_id=f"did:certitrust:{institution_id}",
                issuer_name=institution_name,
                subject_id=credential_data.get("subject_id", f"did:example:{uuid.uuid4()}"),
                subject_name=credential_data.get("subject_name", ""),
                degree=credential_data.get("degree", ""),
                major=credential_data.get("major", ""),
                graduation_date=credential_data.get("graduation_date", ""),
                gpa=credential_data.get("gpa"),
                document_hash=document_hash,
                signature=signature
            )
        
        elif template_type == DocumentType.AADHAAR:
            return W3CVerifiableCredential.create_aadhaar_credential(
                credential_id=credential_id,
                issuer_id=f"did:uidai:issuer",
                masked_aadhaar=credential_data.get("masked_aadhaar", "XXXX-XXXX-0000"),
                name=credential_data.get("name", ""),
                dob=credential_data.get("dob", ""),
                gender=credential_data.get("gender", ""),
                address=credential_data.get("address", {}),
                photo_hash=credential_data.get("photo_hash"),
                signature=signature
            )
        
        else:
            # Generic credential
            now = datetime.now(timezone.utc).isoformat()
            return {
                "@context": [W3CVerifiableCredential.CONTEXT_VC_V2],
                "id": f"urn:uuid:{credential_id}",
                "type": ["VerifiableCredential"],
                "issuer": {
                    "id": f"did:certitrust:{institution_id}",
                    "name": institution_name
                },
                "issuanceDate": now,
                "credentialSubject": credential_data,
                "proof": {
                    "type": "Ed25519Signature2020",
                    "created": now,
                    "proofValue": signature
                } if signature else None
            }
    
    def build_qr_payload(
        self,
        document_id: str,
        document_hash: str,
        institution_id: str,
        signature: str,
        merkle_root: Optional[str] = None,
        credential_type: str = "generic"
    ) -> Dict[str, Any]:
        """
        Builds a W3C VC compliant QR code payload.
        
        Args:
            document_id: Unique document identifier
            document_hash: SHA-256 hash of the document
            institution_id: Issuing institution ID
            signature: Ed25519 signature (base64)
            merkle_root: Optional Merkle root for multi-page docs
            credential_type: Type of credential
            
        Returns:
            QR payload dictionary
        """
        payload = {
            "@context": W3CVerifiableCredential.CONTEXT_VC_V2,
            "type": "VerifiablePresentation",
            "id": document_id,
            "holder": f"did:certitrust:{institution_id}",
            "verificationData": {
                "documentHash": document_hash,
                "signature": signature,
                "signatureType": "Ed25519Signature2020"
            }
        }
        
        if merkle_root:
            payload["verificationData"]["merkleRoot"] = merkle_root
        
        return payload
