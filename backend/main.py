"""
CertiTrust Multi-Tenant Document Verification API
=================================================
FastAPI backend for multi-tenant institutional document issuance and verification.

Features:
- Multi-tenant KMS (Key Management System)
- W3C Verifiable Credentials support
- Merkle Tree tamper localization
- Hash-chain audit trail
- Memory-optimized for 8GB RAM

Version: 2.0.0
"""

# Load environment variables FIRST before any other imports
# This ensures os.getenv() picks up .env values in all modules
import os
from pathlib import Path
from dotenv import load_dotenv

# Find .env file relative to this file (handles both direct and package runs)
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    load_dotenv(_env_file)
else:
    # Also try project root
    _root_env = Path(__file__).parent.parent / "backend" / ".env"
    if _root_env.exists():
        load_dotenv(_root_env)

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Depends, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.background import BackgroundTask
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import shutil
import uuid
import httpx
from datetime import datetime, timezone
import re

# Local imports
try:
    from utils import secure_hash, hash_stream, hash_string
    from crypto import DocumentSigner
    from qr_service import (
        generate_qr, stamp_document, generate_w3c_qr_payload,
        QRConfig, QRPosition
    )
    from services.kms import KMSService, InstitutionSigner, InstitutionKeys, LegacyDocumentSigner
    from services.templates import (
        TemplateEngine, MerkleTree, extract_page_hashes_from_pdf,
        DocumentType, W3CVerifiableCredential
    )
    from services.audit import AuditService, AuditEventType
except ImportError:
    from backend.utils import secure_hash, hash_stream, hash_string
    from backend.crypto import DocumentSigner
    from backend.qr_service import (
        generate_qr, stamp_document, generate_w3c_qr_payload,
        QRConfig, QRPosition
    )
    from backend.services.kms import KMSService, InstitutionSigner, InstitutionKeys, LegacyDocumentSigner
    from backend.services.templates import (
        TemplateEngine, MerkleTree, extract_page_hashes_from_pdf,
        DocumentType, W3CVerifiableCredential
    )
    from backend.services.audit import AuditService, AuditEventType


# ============================================================
# Application Setup
# ============================================================

app = FastAPI(
    title="CertiTrust Multi-Tenant Document Verification",
    description="DPI-3 Multi-Tenant Document Verification & Trust Layer",
    version="2.0.0"
)

# CORS middleware for frontend integration
# Allow localhost:3000 (web), localhost:5173 (Processing frontend), and any CORS_ORIGINS env var
CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS", 
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create a temporary directory for file processing
TEMP_DIR = Path("temp_files")
TEMP_DIR.mkdir(exist_ok=True)

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")


# ============================================================
# Pydantic Models
# ============================================================

class InstitutionOnboard(BaseModel):
    """Request model for institution onboarding."""
    name: str = Field(..., min_length=2, max_length=200)
    slug: str = Field(..., min_length=2, max_length=50, pattern=r'^[a-z0-9-]+$')
    contact_email: Optional[str] = None
    domain: Optional[str] = None


class InstitutionResponse(BaseModel):
    """Response model for institution data."""
    id: str
    name: str
    slug: str
    public_key_pem: str
    created_at: str
    is_active: bool


class DocumentIssueRequest(BaseModel):
    """Request model for document issuance."""
    institution_id: str
    document_type: str = "generic"
    subject_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class VerificationRequest(BaseModel):
    """Request model for document verification."""
    document_hash: str
    signature: str
    institution_id: Optional[str] = None
    public_key_pem: Optional[str] = None  # For ad-hoc verification without institution


class VerificationResponse(BaseModel):
    """Response model for verification result."""
    is_valid: bool
    institution_id: Optional[str] = None
    institution_name: Optional[str] = None
    issued_at: Optional[str] = None
    document_type: Optional[str] = None
    merkle_root: Optional[str] = None
    message: str


class AuditLogResponse(BaseModel):
    """Response model for audit log entries."""
    entries: List[Dict[str, Any]]
    total: int
    chain_valid: bool


class TemplateCreate(BaseModel):
    """Request model for template creation."""
    institution_id: str
    name: str
    template_type: str
    json_schema: Optional[Dict[str, Any]] = None
    ld_context: Optional[Dict[str, Any]] = None
    required_fields: Optional[List[str]] = None
    description: Optional[str] = None


# ============================================================
# Utility Functions
# ============================================================

def cleanup_files(*files):
    """Clean up temporary files."""
    for file in files:
        if isinstance(file, (str, Path)) and os.path.exists(file):
            try:
                os.remove(file)
            except Exception:
                pass


def get_client_info(request: Request) -> tuple:
    """Extract client IP and user agent from request."""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    return ip_address, user_agent


def get_supabase_headers() -> Dict[str, str]:
    """Returns Supabase API headers."""
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json"
    }


# ============================================================
# Admin Routes - Institution Onboarding
# ============================================================

@app.post("/admin/onboard", response_model=InstitutionResponse)
async def onboard_institution(data: InstitutionOnboard, request: Request):
    """
    Onboards a new institution with Ed25519 keypair generation.
    
    - Generates unique Ed25519 keypair
    - Encrypts private key with master service key
    - Stores institution in database
    - Creates audit log entry
    """
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    try:
        # Initialize KMS and generate keys
        kms = KMSService()
        keys = kms.create_institution_keys()
        
        # Prepare institution record
        institution_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        institution_data = {
            "id": institution_id,
            "name": data.name,
            "slug": data.slug,
            "contact_email": data.contact_email,
            "domain": data.domain,
            "public_key_pem": keys.public_key_pem,
            "encrypted_private_key": keys.encrypted_private_key,
            "key_nonce": keys.key_nonce,
            "is_active": True,
            "created_at": now,
            "updated_at": now,
            "key_rotated_at": now
        }
        
        # Store in Supabase
        url = f"{SUPABASE_URL}/rest/v1/institutions"
        headers = get_supabase_headers()
        headers["Prefer"] = "return=representation"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=institution_data)
            
            if response.status_code == 409:
                raise HTTPException(status_code=409, detail="Institution slug already exists")
            
            if response.status_code >= 400:
                raise HTTPException(status_code=response.status_code, detail=response.text)
        
        # Log audit event
        audit = AuditService()
        ip_address, user_agent = get_client_info(request)
        audit.log_event(
            event_type=AuditEventType.INSTITUTION_ONBOARDED,
            institution_id=institution_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"name": data.name, "slug": data.slug}
        )
        
        return InstitutionResponse(
            id=institution_id,
            name=data.name,
            slug=data.slug,
            public_key_pem=keys.public_key_pem,
            created_at=now,
            is_active=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to onboard institution: {e}")


@app.get("/admin/institutions")
async def list_institutions(
    active_only: bool = Query(True, description="Only return active institutions")
):
    """Lists all registered institutions."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    try:
        url = f"{SUPABASE_URL}/rest/v1/institutions"
        params = {"select": "id,name,slug,contact_email,domain,is_active,created_at"}
        
        if active_only:
            params["is_active"] = "eq.true"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=get_supabase_headers(), params=params)
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list institutions: {e}")


@app.get("/admin/institutions/{institution_id}")
async def get_institution(institution_id: str):
    """Gets details of a specific institution."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    try:
        url = f"{SUPABASE_URL}/rest/v1/institutions"
        params = {
            "id": f"eq.{institution_id}",
            "select": "id,name,slug,public_key_pem,contact_email,domain,is_active,created_at,key_rotated_at"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=get_supabase_headers(), params=params)
            response.raise_for_status()
            data = response.json()
            
            if not data:
                raise HTTPException(status_code=404, detail="Institution not found")
            
            return data[0]
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get institution: {e}")


@app.post("/admin/institutions/{institution_id}/rotate-key")
async def rotate_institution_key(institution_id: str, request: Request):
    """Rotates the Ed25519 keypair for an institution."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    try:
        # Generate new keypair
        kms = KMSService()
        keys = kms.create_institution_keys()
        now = datetime.now(timezone.utc).isoformat()
        
        # Update in database
        url = f"{SUPABASE_URL}/rest/v1/institutions"
        params = {"id": f"eq.{institution_id}"}
        
        update_data = {
            "public_key_pem": keys.public_key_pem,
            "encrypted_private_key": keys.encrypted_private_key,
            "key_nonce": keys.key_nonce,
            "key_rotated_at": now,
            "updated_at": now
        }
        
        headers = get_supabase_headers()
        headers["Prefer"] = "return=representation"
        
        async with httpx.AsyncClient() as client:
            response = await client.patch(url, headers=headers, params=params, json=update_data)
            
            if response.status_code == 404 or not response.json():
                raise HTTPException(status_code=404, detail="Institution not found")
            
            response.raise_for_status()
        
        # Log audit event
        audit = AuditService()
        ip_address, user_agent = get_client_info(request)
        audit.log_event(
            event_type=AuditEventType.KEY_ROTATED,
            institution_id=institution_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return {"message": "Key rotated successfully", "key_rotated_at": now}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rotate key: {e}")


# ============================================================
# API Key Management Routes
# ============================================================

try:
    from services.auth import (
        InstitutionAuthService, AuthenticatedInstitution,
        get_authenticated_institution, get_optional_institution
    )
except ImportError:
    from backend.services.auth import (
        InstitutionAuthService, AuthenticatedInstitution,
        get_authenticated_institution, get_optional_institution
    )


@app.post("/admin/institutions/{institution_id}/api-keys")
async def create_institution_api_key(
    institution_id: str,
    name: str = "Default Key",
    expires_in_days: Optional[int] = None,
    rate_limit_per_day: Optional[int] = None
):
    """
    Creates a new API key for an institution.
    
    IMPORTANT: The plaintext key is only returned once! Store it securely.
    
    Args:
        institution_id: UUID of the institution
        name: Friendly name for the key
        expires_in_days: Optional expiration (None = never expires)
        rate_limit_per_day: Optional daily request limit
        
    Returns:
        api_key: The full API key (only shown once!)
        key_metadata: Key details for reference
    """
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    auth_service = InstitutionAuthService()
    
    try:
        api_key, metadata = await auth_service.create_api_key(
            institution_id=institution_id,
            name=name,
            expires_in_days=expires_in_days,
            rate_limit_per_day=rate_limit_per_day
        )
        
        return {
            "api_key": api_key,
            "metadata": metadata,
            "warning": "Store this API key securely. It will not be shown again."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create API key: {e}")


@app.get("/admin/institutions/{institution_id}/api-keys")
async def list_institution_api_keys(institution_id: str):
    """Lists all API keys for an institution (metadata only, no secrets)."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    auth_service = InstitutionAuthService()
    keys = await auth_service.list_api_keys(institution_id)
    
    return {"keys": keys, "count": len(keys)}


@app.delete("/admin/institutions/{institution_id}/api-keys/{key_id}")
async def revoke_institution_api_key(institution_id: str, key_id: str):
    """Revokes an API key."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    auth_service = InstitutionAuthService()
    success = await auth_service.revoke_api_key(key_id, institution_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return {"message": "API key revoked successfully"}


# ============================================================
# Document Issuance Routes
# ============================================================

@app.post("/issue/document")
async def issue_document(
    file: UploadFile = File(...),
    institution_id: Optional[str] = None,
    document_type: str = "generic"
):
    """
    Issues a document by processing it through the CertiTrust pipeline.
    
    Pipeline:
    1. Calculate document hash (SHA-256, chunked)
    2. Extract page hashes and build Merkle tree (for multi-page)
    3. Sign hash with institution's Ed25519 key
    4. Generate W3C VC compliant QR code
    5. Stamp document with QR code
    6. Log to hash-chain audit trail
    7. Return stamped PDF
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")

    file_id = str(uuid.uuid4())
    input_path = TEMP_DIR / f"{file_id}_original.pdf"
    output_path = TEMP_DIR / f"{file_id}_stamped.pdf"

    try:
        # Save the uploaded file
        with open(input_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # 1. Calculate Document Hash (chunked for memory efficiency)
        doc_hash = secure_hash(input_path)

        # 2. Extract page hashes and build Merkle tree
        page_hashes = list(extract_page_hashes_from_pdf(str(input_path)))
        page_hash_values = [ph.hash for ph in page_hashes]
        
        merkle_tree = MerkleTree(page_hash_values)
        merkle_root = merkle_tree.root_hash

        # 3. Sign with appropriate key
        if institution_id:
            try:
                signer = InstitutionSigner(institution_id)
                signature = signer.sign_document(doc_hash)
                issuer_id = institution_id
            except Exception as e:
                # Fall back to legacy signer
                print(f"Warning: Could not load institution key: {e}")
                signer = LegacyDocumentSigner()
                signature = signer.sign_document(doc_hash)
                issuer_id = "legacy"
        else:
            signer = LegacyDocumentSigner()
            signature = signer.sign_document(doc_hash)
            issuer_id = "legacy"

        # 4. Generate W3C VC compliant QR Payload
        payload = generate_w3c_qr_payload(
            document_id=file_id,
            document_hash=doc_hash,
            issuer_id=issuer_id,
            signature=signature,
            merkle_root=merkle_root,
            credential_type=document_type
        )

        # 5. Generate QR Image
        qr_img = generate_qr(payload)

        # 6. Stamp Document
        stamp_document(str(input_path), str(output_path), qr_img)

        # 7. Store in database if Supabase is configured
        if SUPABASE_URL and SUPABASE_KEY and institution_id:
            try:
                doc_record = {
                    "id": file_id,
                    "institution_id": institution_id,
                    "document_hash": doc_hash,
                    "signature": signature,
                    "merkle_root": merkle_root,
                    "page_hashes": [{"page": ph.page_number, "hash": ph.hash} for ph in page_hashes],
                    "document_type": document_type,
                    "file_name": file.filename,
                    "status": "active",
                    "issued_at": datetime.now(timezone.utc).isoformat()
                }
                
                url = f"{SUPABASE_URL}/rest/v1/issued_documents"
                headers = get_supabase_headers()
                headers["Prefer"] = "return=minimal"
                
                async with httpx.AsyncClient() as client:
                    await client.post(url, headers=headers, json=doc_record)
            except Exception as e:
                print(f"Warning: Failed to store document record: {e}")

        # 8. Log to audit trail
        audit = AuditService()
        audit.log_document_issued(
            institution_id=institution_id or "legacy",
            document_id=file_id,
            document_hash=doc_hash,
            signature=signature,
            document_type=document_type
        )

        return FileResponse(
            path=output_path,
            filename=f"stamped_{file.filename}",
            media_type='application/pdf',
            background=BackgroundTask(cleanup_files, input_path, output_path)
        )

    except HTTPException:
        cleanup_files(input_path, output_path)
        raise
    except Exception as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v2/issue/document")
async def issue_document_authenticated(
    file: UploadFile = File(...),
    document_type: str = "generic",
    institution: AuthenticatedInstitution = Depends(get_authenticated_institution)
):
    """
    Issues a document with API key authentication (v2 endpoint).
    
    This is the preferred endpoint for production use. Requires X-API-Key header.
    
    Headers:
        X-API-Key: ctrust_<your-api-key>
    
    Pipeline:
    1. Authenticate institution via API key
    2. Calculate document hash (SHA-256, chunked)
    3. Extract page hashes and build Merkle tree (for multi-page)
    4. Sign hash with institution's Ed25519 key
    5. Generate W3C VC compliant QR code
    6. Stamp document with QR code
    7. Log to hash-chain audit trail
    8. Return stamped PDF
    
    Security:
    - Institution is authenticated via hashed API key
    - Only active institutions can issue documents
    - Rate limits are enforced if configured
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")

    file_id = str(uuid.uuid4())
    input_path = TEMP_DIR / f"{file_id}_original.pdf"
    output_path = TEMP_DIR / f"{file_id}_stamped.pdf"

    try:
        # Save the uploaded file
        with open(input_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # 1. Calculate Document Hash (chunked for memory efficiency)
        doc_hash = secure_hash(input_path)

        # 2. Extract page hashes and build Merkle tree
        page_hashes = list(extract_page_hashes_from_pdf(str(input_path)))
        page_hash_values = [ph.hash for ph in page_hashes]
        
        merkle_tree = MerkleTree(page_hash_values)
        merkle_root = merkle_tree.root_hash

        # 3. Sign with institution's key (authenticated)
        try:
            signer = InstitutionSigner(institution.id)
            signature = signer.sign_document(doc_hash)
            issuer_id = institution.id
        except Exception as e:
            raise HTTPException(
                status_code=500, 
                detail=f"Failed to sign document: {e}"
            )

        # 4. Generate W3C VC compliant QR Payload
        payload = generate_w3c_qr_payload(
            document_id=file_id,
            document_hash=doc_hash,
            issuer_id=issuer_id,
            signature=signature,
            merkle_root=merkle_root,
            credential_type=document_type
        )

        # 5. Generate QR Image
        qr_img = generate_qr(payload)

        # 6. Stamp Document
        stamp_document(str(input_path), str(output_path), qr_img)

        # 7. Store in database
        if SUPABASE_URL and SUPABASE_KEY:
            try:
                doc_record = {
                    "id": file_id,
                    "institution_id": institution.id,
                    "document_hash": doc_hash,
                    "signature": signature,
                    "merkle_root": merkle_root,
                    "page_hashes": [{"page": ph.page_number, "hash": ph.hash} for ph in page_hashes],
                    "document_type": document_type,
                    "file_name": file.filename,
                    "status": "active",
                    "issued_at": datetime.now(timezone.utc).isoformat()
                }
                
                url = f"{SUPABASE_URL}/rest/v1/issued_documents"
                headers = get_supabase_headers()
                headers["Prefer"] = "return=minimal"
                
                async with httpx.AsyncClient() as client:
                    await client.post(url, headers=headers, json=doc_record)
            except Exception as e:
                print(f"Warning: Failed to store document record: {e}")

        # 8. Log to audit trail
        audit = AuditService()
        audit.log_document_issued(
            institution_id=institution.id,
            document_id=file_id,
            document_hash=doc_hash,
            signature=signature,
            document_type=document_type
        )

        # Include rate limit info in headers if applicable
        response_headers = {}
        if institution.rate_limit_remaining is not None:
            response_headers["X-RateLimit-Remaining"] = str(institution.rate_limit_remaining - 1)

        return FileResponse(
            path=output_path,
            filename=f"stamped_{file.filename}",
            media_type='application/pdf',
            headers=response_headers,
            background=BackgroundTask(cleanup_files, input_path, output_path)
        )

    except HTTPException:
        cleanup_files(input_path, output_path)
        raise
    except Exception as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/issue/academic")
async def issue_academic_credential(
    file: UploadFile = File(...),
    institution_id: str = None,
    student_name: str = None,
    degree: str = None,
    major: str = None,
    graduation_date: str = None,
    gpa: Optional[float] = None
):
    """
    Issues an academic credential following W3C Verifiable Credentials standard.
    """
    if not institution_id:
        raise HTTPException(status_code=400, detail="institution_id is required")
    
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")
    
    file_id = str(uuid.uuid4())
    input_path = TEMP_DIR / f"{file_id}_original.pdf"
    output_path = TEMP_DIR / f"{file_id}_stamped.pdf"
    
    try:
        # Save file
        with open(input_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Hash document
        doc_hash = secure_hash(input_path)
        
        # Get signer
        try:
            signer = InstitutionSigner(institution_id)
            
            # Get institution info
            url = f"{SUPABASE_URL}/rest/v1/institutions"
            params = {"id": f"eq.{institution_id}", "select": "name"}
            
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=get_supabase_headers(), params=params)
                inst_data = response.json()
                institution_name = inst_data[0]["name"] if inst_data else "Unknown Institution"
                
        except Exception:
            signer = LegacyDocumentSigner()
            institution_name = "CertiTrust"
        
        # Sign
        signature = signer.sign_document(doc_hash)
        
        # Create W3C VC
        credential = W3CVerifiableCredential.create_academic_credential(
            credential_id=file_id,
            issuer_id=f"did:certitrust:{institution_id}",
            issuer_name=institution_name,
            subject_id=f"did:student:{hash_string(student_name or '')}",
            subject_name=student_name or "",
            degree=degree or "",
            major=major or "",
            graduation_date=graduation_date or "",
            gpa=gpa,
            document_hash=doc_hash,
            signature=signature
        )
        
        # Generate QR with VC payload
        qr_payload = {
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": "AcademicCredential",
            "id": file_id,
            "issuer": institution_id,
            "hash": doc_hash,
            "sig": signature
        }
        
        qr_img = generate_qr(qr_payload)
        stamp_document(str(input_path), str(output_path), qr_img)
        
        # Audit log
        audit = AuditService()
        audit.log_document_issued(
            institution_id=institution_id,
            document_id=file_id,
            document_hash=doc_hash,
            signature=signature,
            document_type="academic"
        )
        
        return FileResponse(
            path=output_path,
            filename=f"credential_{file.filename}",
            media_type='application/pdf',
            background=BackgroundTask(cleanup_files, input_path, output_path)
        )
        
    except HTTPException:
        cleanup_files(input_path, output_path)
        raise
    except Exception as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# Verification Routes
# ============================================================

@app.post("/verify/document", response_model=VerificationResponse)
async def verify_document(data: VerificationRequest, request: Request):
    """
    Verifies a document's hash and signature.
    
    Steps:
    1. Look up document by hash in database
    2. Load institution's public key
    3. Verify Ed25519 signature
    4. Log verification attempt
    """
    ip_address, user_agent = get_client_info(request)
    audit = AuditService()
    
    try:
        # If institution_id provided, verify directly
        if data.institution_id:
            try:
                signer = InstitutionSigner(data.institution_id)
                is_valid = signer.verify_signature(data.document_hash, data.signature)
                
                if is_valid:
                    audit.log_verification(
                        document_hash=data.document_hash,
                        is_valid=True,
                        institution_id=data.institution_id,
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                    
                    return VerificationResponse(
                        is_valid=True,
                        institution_id=data.institution_id,
                        message="Document signature verified successfully"
                    )
                    
            except Exception as e:
                pass  # Fall through to legacy check
        
        # Try ad-hoc verification with provided public key
        if data.public_key_pem:
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import ed25519
                import base64
                
                public_key = serialization.load_pem_public_key(
                    data.public_key_pem.encode('utf-8')
                )
                signature_bytes = base64.b64decode(data.signature)
                message = data.document_hash.encode('utf-8')
                
                try:
                    public_key.verify(signature_bytes, message)
                    is_valid = True
                except Exception:
                    is_valid = False
                    
                audit.log_verification(
                    document_hash=data.document_hash,
                    is_valid=is_valid,
                    institution_id=data.institution_id,
                    failure_reason=None if is_valid else "Signature verification failed",
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                if is_valid:
                    return VerificationResponse(
                        is_valid=True,
                        message="Document signature verified successfully (ad-hoc key)"
                    )
                    
                return VerificationResponse(
                    is_valid=False,
                    message="Signature verification failed (ad-hoc key)"
                )
            except Exception as e:
                pass  # Fall through to legacy check
        
        # Try legacy verification
        legacy_signer = LegacyDocumentSigner()
        is_valid = legacy_signer.verify_signature(data.document_hash, data.signature)
        
        audit.log_verification(
            document_hash=data.document_hash,
            is_valid=is_valid,
            institution_id=data.institution_id,
            failure_reason=None if is_valid else "Signature verification failed",
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        if is_valid:
            return VerificationResponse(
                is_valid=True,
                message="Document signature verified successfully (legacy mode)"
            )
        
        return VerificationResponse(
            is_valid=False,
            message="Signature verification failed"
        )
        
    except Exception as e:
        audit.log_verification(
            document_hash=data.document_hash,
            is_valid=False,
            failure_reason=str(e),
            ip_address=ip_address,
            user_agent=user_agent
        )
        raise HTTPException(status_code=500, detail=f"Verification error: {e}")


@app.post("/verify/file")
async def verify_file(
    file: UploadFile = File(...),
    expected_hash: Optional[str] = None,
    request: Request = None
):
    """
    Verifies an uploaded stamped PDF file.
    
    Pipeline:
    1. Extract QR code using high-DPI rendering (300 DPI)
    2. Parse W3C VC payload from QR
    3. Look up institution by issuer_id
    4. Verify Ed25519 signature using institution's public key
    5. Return comprehensive verification result
    
    IMPORTANT: The hash in the QR is the ORIGINAL document hash (before stamping).
    The stamped PDF will have a different hash - this is expected.
    We verify the signature against the ORIGINAL hash from the QR.
    """
    file_id = str(uuid.uuid4())
    temp_path = TEMP_DIR / f"{file_id}_verify.pdf"
    ip_address, user_agent = get_client_info(request) if request else (None, None)
    
    try:
        # Save file
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Import scanner service
        try:
            from services.scanner import (
                PDFQRScanner, QRPayload, CleanDocumentHasher,
                verify_document_signature, VerificationErrorCode
            )
        except ImportError:
            from backend.services.scanner import (
                PDFQRScanner, QRPayload, CleanDocumentHasher,
                verify_document_signature, VerificationErrorCode
            )
        
        # Step 1: Extract QR code using high-DPI scanner
        scanner = PDFQRScanner(dpi=300)
        qr_data = scanner.extract_qr_from_page(str(temp_path), page_num=0)
        
        if not qr_data:
            # Try all pages
            qr_data, found_page = scanner.scan_all_pages(str(temp_path))
        
        if not qr_data:
            # Still calculate hash for backwards compatibility
            from utils import secure_hash
            file_hash = secure_hash(str(temp_path))
            
            return JSONResponse(
                status_code=200,
                content={
                    "valid": False,
                    "error_code": VerificationErrorCode.QR_NOT_FOUND.value,
                    "message": "No QR code found in document. Is this a CertiTrust stamped document?",
                    "file_name": file.filename,
                    "calculated_hash": file_hash
                }
            )
        
        # Step 2: Parse QR payload
        try:
            payload = QRPayload.parse(qr_data)
        except Exception as e:
            return JSONResponse(
                status_code=200,
                content={
                    "valid": False,
                    "error_code": VerificationErrorCode.PAYLOAD_READ_FAIL.value,
                    "message": f"Invalid QR payload: {e}",
                    "raw_qr_data": qr_data,
                    "file_name": file.filename
                }
            )
        
        # Step 3: Calculate current file hash (for reference only)
        hasher = CleanDocumentHasher()
        current_file_hash = hasher.calculate_clean_hash(str(temp_path))
        
        # Base result
        result = {
            "valid": False,
            "file_name": file.filename,
            "document_id": payload.document_id,
            "issuer_id": payload.issuer_id,
            "original_hash": payload.document_hash,
            "signature": payload.signature[:20] + "..." if len(payload.signature) > 20 else payload.signature,
            "merkle_root": payload.merkle_root,
            "credential_type": payload.credential_type,
            "current_file_hash": current_file_hash,
            "hash_note": "The original_hash is from the QR (pre-stamp). current_file_hash differs because QR was added."
        }
        
        # Compare with expected hash if provided
        if expected_hash:
            try:
                from utils import compare_hashes
            except ImportError:
                from backend.utils import compare_hashes
            result["expected_hash_matches"] = compare_hashes(payload.document_hash, expected_hash)
        
        # Step 4: Look up institution and verify signature
        institution_data = None
        institution_name = None
        public_key_pem = None
        
        if payload.issuer_id and payload.issuer_id != "legacy":
            try:
                url = f"{SUPABASE_URL}/rest/v1/institutions"
                params = {
                    "id": f"eq.{payload.issuer_id}",
                    "select": "id,name,slug,public_key_pem,is_active"
                }
                
                async with httpx.AsyncClient() as client:
                    response = await client.get(url, headers=get_supabase_headers(), params=params)
                    if response.status_code == 200:
                        data = response.json()
                        if data:
                            institution_data = data[0]
                            institution_name = institution_data.get("name")
                            public_key_pem = institution_data.get("public_key_pem")
                            result["institution_name"] = institution_name
                            result["institution_active"] = institution_data.get("is_active", False)
                            
            except Exception as e:
                result["institution_lookup_error"] = str(e)
        
        # Step 5: Verify signature
        signature_verified = False
        
        if public_key_pem:
            # Verify against institutional key
            signature_verified = verify_document_signature(
                payload.document_hash,
                payload.signature,
                public_key_pem
            )
            result["signature_verified_with"] = "institution_key"
        else:
            # Try legacy verification
            try:
                legacy_signer = LegacyDocumentSigner()
                signature_verified = legacy_signer.verify_signature(
                    payload.document_hash,
                    payload.signature
                )
                result["signature_verified_with"] = "legacy_key"
            except Exception:
                pass
        
        result["signature_valid"] = signature_verified
        
        if signature_verified:
            result["valid"] = True
            result["error_code"] = VerificationErrorCode.SUCCESS.value
            result["message"] = "Document signature verified successfully"
        else:
            result["error_code"] = VerificationErrorCode.SIGNATURE_MISMATCH.value
            result["message"] = "Signature verification failed. Document may have been tampered with or signed by unknown issuer."
        
        # Step 6: Run Forensic Analysis Pipeline
        forensic_report = None
        trust_score_result = None
        try:
            # Import forensic service (lazy import to avoid startup overhead)
            try:
                from services.forensics import ForensicService
                from utils import quick_trust_score
            except ImportError:
                from backend.services.forensics import ForensicService
                from backend.utils import quick_trust_score
            
            forensic_service = ForensicService(enable_cloud=False)  # Disable cloud by default
            
            # Run forensic analysis on the PDF
            forensic_report = await forensic_service.analyze_pdf(
                pdf_path=str(temp_path),
                document_id=payload.document_id,
                run_tier1=True,  # ELA
                run_tier2=True,  # Local AI
                run_tier3=False,  # Cloud (disabled by default)
                run_metadata=True
            )
            
            # Calculate Trust Score using weighted formula
            trust_score_result = quick_trust_score(
                crypto_valid=signature_verified,
                forensic_report=forensic_report.to_dict() if forensic_report else None
            )
            
            # Add forensic results to response
            result["forensic_analysis"] = forensic_report.to_dict() if forensic_report else None
            result["trust_score"] = trust_score_result
            
            # Update overall validity based on trust score
            if trust_score_result:
                trust_grade = trust_score_result.get("grade", "F")
                if trust_grade in ["D", "F"] and signature_verified:
                    result["message"] += f" WARNING: Low trust score ({trust_grade}) - forensic analysis detected potential manipulation."
                    
        except Exception as forensic_error:
            # Don't fail verification due to forensic analysis errors
            result["forensic_analysis_error"] = str(forensic_error)
        
        # Step 7: Log verification attempt with forensic data
        try:
            audit = AuditService()
            
            # Include forensic data in audit metadata
            audit_metadata = {}
            if forensic_report:
                audit_metadata["forensic_status"] = forensic_report.overall_status.value if hasattr(forensic_report.overall_status, 'value') else str(forensic_report.overall_status)
                audit_metadata["tiers_executed"] = forensic_report.tiers_executed
            if trust_score_result:
                audit_metadata["trust_score"] = trust_score_result.get("trust_score")
                audit_metadata["trust_grade"] = trust_score_result.get("grade")
            
            audit.log_verification(
                document_hash=payload.document_hash,
                is_valid=signature_verified,
                institution_id=payload.issuer_id if payload.issuer_id != "legacy" else None,
                failure_reason=None if signature_verified else "Signature verification failed",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata=audit_metadata if audit_metadata else None
            )
        except Exception:
            pass  # Don't fail verification due to audit logging
        
        return result
        
    except Exception as e:
        return JSONResponse(
            status_code=200,
            content={
                "valid": False,
                "error_code": VerificationErrorCode.INTERNAL_ERROR.value,
                "message": f"Verification error: {str(e)}",
                "file_name": file.filename
            }
        )
        
    finally:
        cleanup_files(temp_path)


@app.get("/verify/document/{document_id}")
async def get_document_verification(document_id: str):
    """Gets verification details for a specific document ID."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    try:
        url = f"{SUPABASE_URL}/rest/v1/issued_documents"
        params = {
            "id": f"eq.{document_id}",
            "select": "id,institution_id,document_hash,document_type,status,issued_at,merkle_root"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=get_supabase_headers(), params=params)
            response.raise_for_status()
            data = response.json()
            
            if not data:
                raise HTTPException(status_code=404, detail="Document not found")
            
            doc = data[0]
            
            # Get institution info
            inst_url = f"{SUPABASE_URL}/rest/v1/institutions"
            inst_params = {"id": f"eq.{doc['institution_id']}", "select": "name,public_key_pem"}
            
            inst_response = await client.get(inst_url, headers=get_supabase_headers(), params=inst_params)
            inst_data = inst_response.json()
            
            if inst_data:
                doc["institution_name"] = inst_data[0]["name"]
                doc["public_key_pem"] = inst_data[0]["public_key_pem"]
            
            return doc
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {e}")


# ============================================================
# Audit Routes
# ============================================================

@app.get("/audit/logs")
async def get_audit_logs(
    institution_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Retrieves audit logs with optional filtering."""
    audit = AuditService()
    
    event_type_enum = None
    if event_type:
        try:
            event_type_enum = AuditEventType(event_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid event type: {event_type}")
    
    entries = audit.get_audit_trail(
        institution_id=institution_id,
        event_type=event_type_enum,
        limit=limit,
        offset=offset
    )
    
    # Check chain integrity
    is_valid, broken_at = audit.verify_chain_integrity(institution_id, limit=limit)
    
    return AuditLogResponse(
        entries=entries,
        total=len(entries),
        chain_valid=is_valid
    )


@app.get("/audit/verify-chain")
async def verify_audit_chain(institution_id: Optional[str] = None):
    """Verifies the integrity of the audit hash chain."""
    audit = AuditService()
    
    try:
        is_valid, broken_position = audit.verify_chain_integrity(institution_id)
        
        return {
            "chain_valid": is_valid,
            "broken_at_position": broken_position,
            "message": "Chain integrity verified" if is_valid else f"Chain broken at position {broken_position}"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chain verification failed: {e}")


# ============================================================
# Template Routes
# ============================================================

@app.post("/templates")
async def create_template(data: TemplateCreate, request: Request):
    """Creates a new document template for an institution."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    try:
        template_type = DocumentType(data.template_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid template type: {data.template_type}")
    
    try:
        template_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        template_data = {
            "id": template_id,
            "institution_id": data.institution_id,
            "name": data.name,
            "template_type": template_type.value,
            "json_schema": data.json_schema,
            "ld_context": data.ld_context,
            "required_fields": data.required_fields or [],
            "description": data.description,
            "is_active": True,
            "created_at": now,
            "updated_at": now
        }
        
        url = f"{SUPABASE_URL}/rest/v1/document_templates"
        headers = get_supabase_headers()
        headers["Prefer"] = "return=representation"
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=template_data)
            response.raise_for_status()
        
        # Audit log
        audit = AuditService()
        ip_address, user_agent = get_client_info(request)
        audit.log_event(
            event_type=AuditEventType.TEMPLATE_CREATED,
            institution_id=data.institution_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"template_id": template_id, "name": data.name}
        )
        
        return {"id": template_id, "message": "Template created successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create template: {e}")


@app.get("/templates")
async def list_templates(institution_id: Optional[str] = None):
    """Lists available document templates."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured")
    
    try:
        url = f"{SUPABASE_URL}/rest/v1/document_templates"
        params = {"select": "*", "is_active": "eq.true"}
        
        if institution_id:
            params["institution_id"] = f"eq.{institution_id}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=get_supabase_headers(), params=params)
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list templates: {e}")


# ============================================================
# AI Image Detection Endpoint
# ============================================================

class AIDetectionResponse(BaseModel):
    """Response model for AI image detection."""
    status: str
    ai_manipulation_likely: bool
    trust_score: float
    confidence: float
    scores: Dict[str, float]
    model: str
    processing_time_ms: float


@app.post("/ai/detect-image", response_model=AIDetectionResponse)
async def detect_ai_image(
    file: UploadFile = File(...),
    request: Request = None
):
    """
    Detects if an uploaded image is AI-generated or manipulated.
    
    Uses the umm-maybe/AI-image-detector model (~92% accuracy).
    Optimized for JPEG images but supports PNG, WEBP, etc.
    
    Returns:
    - ai_manipulation_likely: True if artificial score > 0.2
    - trust_score: Percentage indicating human/authentic likelihood
    - confidence: Model confidence in the prediction
    - scores: Raw artificial/human probabilities
    """
    import time
    start_time = time.time()
    
    # Validate file type
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=400,
            detail="Only image files are allowed (JPEG, PNG, WEBP, etc.)"
        )
    
    file_id = str(uuid.uuid4())
    temp_path = TEMP_DIR / f"{file_id}_ai_detect{Path(file.filename).suffix}"
    
    try:
        # Save file
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Import AI detector from forensics service
        try:
            from services.forensics import LazyModelLoader
        except ImportError:
            from backend.services.forensics import LazyModelLoader
        
        from PIL import Image
        import torch
        
        # Load image
        img = Image.open(temp_path).convert("RGB")
        
        # Resize for memory efficiency (max 2048px)
        max_dim = 2048
        if max(img.size) > max_dim:
            ratio = max_dim / max(img.size)
            new_size = (int(img.size[0] * ratio), int(img.size[1] * ratio))
            img = img.resize(new_size, Image.Resampling.LANCZOS)
        
        # Load model (lazy loaded, CPU optimized)
        processor, model = LazyModelLoader.load_ai_detector()
        
        if not processor or not model:
            raise HTTPException(
                status_code=503,
                detail="AI detector model not available. Install torch and transformers."
            )
        
        # Run inference
        inputs = processor(images=img, return_tensors="pt")
        inputs = {k: v.to("cpu") for k, v in inputs.items()}
        
        with torch.no_grad():
            outputs = model(**inputs)
        
        probs = torch.softmax(outputs.logits, dim=1)[0]
        
        # Get scores (model has human=0, artificial=1 labels)
        human_score = float(probs[0])
        artificial_score = float(probs[1])
        
        # Cleanup
        img.close()
        
        processing_time = (time.time() - start_time) * 1000
        
        # Calculate trust score (inverse of manipulation likelihood)
        trust_score = round(human_score * 100, 2)
        
        return AIDetectionResponse(
            status="analyzed",
            ai_manipulation_likely=artificial_score > 0.2,
            trust_score=trust_score,
            confidence=round(max(human_score, artificial_score), 4),
            scores={
                "human": round(human_score, 4),
                "artificial": round(artificial_score, 4)
            },
            model="umm-maybe/AI-image-detector",
            processing_time_ms=round(processing_time, 2)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"AI detection failed: {str(e)}"
        )
    finally:
        cleanup_files(temp_path)


@app.post("/verify-document")
async def verify_document_legacy(
    file: UploadFile = File(...),
    request: Request = None
):
    """
    Legacy endpoint for document verification with AI check.
    
    Combines QR verification (always true for now) with AI detection.
    Compatible with the Processing frontend at localhost:5173.
    """
    import time
    start_time = time.time()
    
    # Validate file type
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=400,
            detail="Only image files are allowed"
        )
    
    file_id = str(uuid.uuid4())
    temp_path = TEMP_DIR / f"{file_id}_verify{Path(file.filename).suffix}"
    
    try:
        # Save file
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # QR check (placeholder - always true for now)
        qr_verified = True
        
        # AI detection
        try:
            from services.forensics import LazyModelLoader
        except ImportError:
            from backend.services.forensics import LazyModelLoader
        
        from PIL import Image
        import torch
        
        img = Image.open(temp_path).convert("RGB")
        
        # Resize for memory
        max_dim = 2048
        if max(img.size) > max_dim:
            ratio = max_dim / max(img.size)
            new_size = (int(img.size[0] * ratio), int(img.size[1] * ratio))
            img = img.resize(new_size, Image.Resampling.LANCZOS)
        
        processor, model = LazyModelLoader.load_ai_detector()
        
        ai_result = {
            "ai_manipulation_likely": False,
            "trust_score": 100.0,
            "scores": {"human": 1.0, "artificial": 0.0}
        }
        
        if processor and model:
            inputs = processor(images=img, return_tensors="pt")
            inputs = {k: v.to("cpu") for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = model(**inputs)
            
            probs = torch.softmax(outputs.logits, dim=1)[0]
            human_score = float(probs[0])
            artificial_score = float(probs[1])
            
            ai_result = {
                "ai_manipulation_likely": artificial_score > 0.2,
                "trust_score": round(human_score * 100, 2),
                "scores": {
                    "human": round(human_score, 4),
                    "artificial": round(artificial_score, 4)
                }
            }
        
        img.close()
        
        return {
            "status": "verified",
            "qr_verified": qr_verified,
            "ai_check": ai_result,
            "processing_time_ms": round((time.time() - start_time) * 1000, 2)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Verification failed: {str(e)}"
        )
    finally:
        cleanup_files(temp_path)


# ============================================================
# Health Check
# ============================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    status = {
        "status": "healthy",
        "version": "2.0.0",
        "supabase_configured": bool(SUPABASE_URL and SUPABASE_KEY)
    }
    
    # Check Supabase connectivity
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{SUPABASE_URL}/rest/v1/",
                    headers=get_supabase_headers(),
                    timeout=5.0
                )
                status["supabase_connected"] = response.status_code < 500
        except Exception:
            status["supabase_connected"] = False
    
    return status


# ============================================================
# Legacy Compatibility
# ============================================================

def log_audit_event(doc_hash: str):
    """
    Legacy function for backward compatibility.
    Logs the document hash to Supabase audit_logs table.
    """
    if not SUPABASE_URL or not SUPABASE_KEY:
        print("WARNING: Supabase credentials not found. Skipping audit log.")
        return

    try:
        audit = AuditService()
        audit.log_event(
            event_type=AuditEventType.DOCUMENT_ISSUED,
            document_hash=doc_hash
        )
    except Exception as e:
        print(f"Exception logging to Supabase: {e}")
