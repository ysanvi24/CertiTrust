"""
Institution Authorization Service for CertiTrust.

Provides API key-based authentication for institutions to securely issue documents.
Uses SHA-256 hashed API keys stored in Supabase for security.

Features:
- API key generation with cryptographically secure random bytes
- Hash-based key verification (keys never stored in plaintext)
- Optional rate limiting support
- Audit logging of auth events

Author: CertiTrust Team
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from dataclasses import dataclass
from enum import Enum

import httpx
from fastapi import HTTPException, Header, Depends
from dotenv import load_dotenv

load_dotenv()


class AuthErrorCode(str, Enum):
    """Authentication error codes."""
    MISSING_API_KEY = "AUTH_001"
    INVALID_API_KEY = "AUTH_002"
    EXPIRED_API_KEY = "AUTH_003"
    REVOKED_API_KEY = "AUTH_004"
    INACTIVE_INSTITUTION = "AUTH_005"
    RATE_LIMIT_EXCEEDED = "AUTH_006"


@dataclass
class AuthenticatedInstitution:
    """Represents an authenticated institution."""
    id: str
    name: str
    slug: str
    is_active: bool
    public_key_pem: str
    api_key_id: str
    rate_limit_remaining: Optional[int] = None


class InstitutionAuthService:
    """
    Handles institution authentication via API keys.
    
    Security Design:
    - API keys are 32-byte (256-bit) cryptographically random tokens
    - Keys are prefixed with 'ctrust_' for easy identification
    - Only SHA-256 hash of the key is stored in database
    - Keys can have expiration dates and rate limits
    """
    
    API_KEY_PREFIX = "ctrust_"
    API_KEY_BYTES = 32
    
    def __init__(self):
        self._supabase_url = os.getenv("SUPABASE_URL")
        self._supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        
    def _get_headers(self) -> dict:
        """Get Supabase API headers."""
        return {
            "apikey": self._supabase_key,
            "Authorization": f"Bearer {self._supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        }
    
    @classmethod
    def generate_api_key(cls) -> str:
        """
        Generate a new cryptographically secure API key.
        
        Returns:
            str: API key in format 'ctrust_<64-char-hex>'
        """
        random_bytes = secrets.token_bytes(cls.API_KEY_BYTES)
        return f"{cls.API_KEY_PREFIX}{random_bytes.hex()}"
    
    @classmethod
    def hash_api_key(cls, api_key: str) -> str:
        """
        Create a SHA-256 hash of the API key for storage.
        
        Args:
            api_key: The plaintext API key
            
        Returns:
            str: Hex-encoded SHA-256 hash
        """
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    async def create_api_key(
        self,
        institution_id: str,
        name: str = "Default Key",
        expires_in_days: Optional[int] = None,
        rate_limit_per_day: Optional[int] = None
    ) -> Tuple[str, dict]:
        """
        Create a new API key for an institution.
        
        Args:
            institution_id: UUID of the institution
            name: Friendly name for the key
            expires_in_days: Optional expiration (None = never expires)
            rate_limit_per_day: Optional daily request limit
            
        Returns:
            Tuple[str, dict]: (plaintext_key, key_metadata)
            
        IMPORTANT: The plaintext key is only returned once and never stored!
        """
        # Generate new key
        api_key = self.generate_api_key()
        key_hash = self.hash_api_key(api_key)
        
        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).isoformat()
        
        # Store in database
        key_data = {
            "institution_id": institution_id,
            "name": name,
            "key_hash": key_hash,
            "key_prefix": api_key[:12],  # Store prefix for identification
            "expires_at": expires_at,
            "rate_limit_per_day": rate_limit_per_day,
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self._supabase_url}/rest/v1/institution_api_keys",
                headers=self._get_headers(),
                json=key_data
            )
            
            if response.status_code not in [200, 201]:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to create API key: {response.text}"
                )
            
            created = response.json()
            if isinstance(created, list):
                created = created[0]
        
        return api_key, {
            "id": created["id"],
            "name": name,
            "key_prefix": api_key[:12],
            "expires_at": expires_at,
            "rate_limit_per_day": rate_limit_per_day,
            "created_at": created["created_at"]
        }
    
    async def validate_api_key(self, api_key: str) -> AuthenticatedInstitution:
        """
        Validate an API key and return the authenticated institution.
        
        Args:
            api_key: The API key from the request header
            
        Returns:
            AuthenticatedInstitution with validated institution details
            
        Raises:
            HTTPException: If validation fails
        """
        # Check format
        if not api_key or not api_key.startswith(self.API_KEY_PREFIX):
            raise HTTPException(
                status_code=401,
                detail={
                    "error_code": AuthErrorCode.INVALID_API_KEY.value,
                    "message": "Invalid API key format"
                }
            )
        
        # Hash the provided key
        key_hash = self.hash_api_key(api_key)
        
        # Look up key in database
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self._supabase_url}/rest/v1/institution_api_keys",
                headers=self._get_headers(),
                params={
                    "key_hash": f"eq.{key_hash}",
                    "select": "id,institution_id,name,expires_at,rate_limit_per_day,is_active,daily_request_count,last_request_date"
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=500,
                    detail="Auth service error"
                )
            
            keys = response.json()
            
            if not keys:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "error_code": AuthErrorCode.INVALID_API_KEY.value,
                        "message": "Invalid API key"
                    }
                )
            
            key_data = keys[0]
        
        # Check if key is active
        if not key_data.get("is_active", False):
            raise HTTPException(
                status_code=401,
                detail={
                    "error_code": AuthErrorCode.REVOKED_API_KEY.value,
                    "message": "API key has been revoked"
                }
            )
        
        # Check expiration
        if key_data.get("expires_at"):
            expires_at = datetime.fromisoformat(key_data["expires_at"].replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_at:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "error_code": AuthErrorCode.EXPIRED_API_KEY.value,
                        "message": "API key has expired"
                    }
                )
        
        # Check rate limit
        rate_limit = key_data.get("rate_limit_per_day")
        rate_remaining = None
        
        if rate_limit:
            today = datetime.now(timezone.utc).date().isoformat()
            last_request_date = key_data.get("last_request_date")
            daily_count = key_data.get("daily_request_count", 0)
            
            if last_request_date == today:
                if daily_count >= rate_limit:
                    raise HTTPException(
                        status_code=429,
                        detail={
                            "error_code": AuthErrorCode.RATE_LIMIT_EXCEEDED.value,
                            "message": f"Daily rate limit of {rate_limit} requests exceeded"
                        }
                    )
                rate_remaining = rate_limit - daily_count
            else:
                # New day, reset counter
                rate_remaining = rate_limit
        
        # Get institution details
        institution_id = key_data["institution_id"]
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self._supabase_url}/rest/v1/institutions",
                headers=self._get_headers(),
                params={
                    "id": f"eq.{institution_id}",
                    "select": "id,name,slug,is_active,public_key_pem"
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=500,
                    detail="Failed to fetch institution"
                )
            
            institutions = response.json()
            
            if not institutions:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "error_code": AuthErrorCode.INVALID_API_KEY.value,
                        "message": "Institution not found"
                    }
                )
            
            institution = institutions[0]
        
        # Check institution is active
        if not institution.get("is_active", False):
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": AuthErrorCode.INACTIVE_INSTITUTION.value,
                    "message": "Institution account is inactive"
                }
            )
        
        # Update request counter (fire-and-forget, don't block)
        today = datetime.now(timezone.utc).date().isoformat()
        try:
            async with httpx.AsyncClient() as client:
                await client.patch(
                    f"{self._supabase_url}/rest/v1/institution_api_keys",
                    headers=self._get_headers(),
                    params={"id": f"eq.{key_data['id']}"},
                    json={
                        "last_request_date": today,
                        "daily_request_count": 1 if key_data.get("last_request_date") != today else (key_data.get("daily_request_count", 0) + 1),
                        "last_used_at": datetime.now(timezone.utc).isoformat()
                    }
                )
        except Exception:
            pass  # Don't fail request if counter update fails
        
        return AuthenticatedInstitution(
            id=institution["id"],
            name=institution["name"],
            slug=institution["slug"],
            is_active=institution["is_active"],
            public_key_pem=institution["public_key_pem"],
            api_key_id=key_data["id"],
            rate_limit_remaining=rate_remaining
        )
    
    async def revoke_api_key(self, key_id: str, institution_id: str) -> bool:
        """
        Revoke an API key.
        
        Args:
            key_id: UUID of the API key
            institution_id: UUID of the institution (for verification)
            
        Returns:
            bool: True if revoked successfully
        """
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self._supabase_url}/rest/v1/institution_api_keys",
                headers=self._get_headers(),
                params={
                    "id": f"eq.{key_id}",
                    "institution_id": f"eq.{institution_id}"
                },
                json={
                    "is_active": False,
                    "revoked_at": datetime.now(timezone.utc).isoformat()
                }
            )
            
            return response.status_code == 200
    
    async def list_api_keys(self, institution_id: str) -> list:
        """
        List all API keys for an institution.
        
        Args:
            institution_id: UUID of the institution
            
        Returns:
            list: API key metadata (no sensitive data)
        """
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self._supabase_url}/rest/v1/institution_api_keys",
                headers=self._get_headers(),
                params={
                    "institution_id": f"eq.{institution_id}",
                    "select": "id,name,key_prefix,expires_at,rate_limit_per_day,is_active,created_at,last_used_at"
                }
            )
            
            if response.status_code != 200:
                return []
            
            return response.json()


# Dependency for FastAPI endpoints
async def get_authenticated_institution(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> AuthenticatedInstitution:
    """
    FastAPI dependency to authenticate institution from X-API-Key header.
    
    Usage:
        @app.post("/issue/document")
        async def issue_document(
            institution: AuthenticatedInstitution = Depends(get_authenticated_institution),
            ...
        ):
            # institution.id, institution.name, etc. available
    """
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": AuthErrorCode.MISSING_API_KEY.value,
                "message": "X-API-Key header required"
            }
        )
    
    auth_service = InstitutionAuthService()
    return await auth_service.validate_api_key(x_api_key)


async def get_optional_institution(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> Optional[AuthenticatedInstitution]:
    """
    Optional auth dependency - returns None if no key provided.
    
    Use for endpoints that support both authenticated and anonymous access.
    """
    if not x_api_key:
        return None
    
    try:
        auth_service = InstitutionAuthService()
        return await auth_service.validate_api_key(x_api_key)
    except HTTPException:
        return None
