"""
Key Management System (KMS) Service for CertiTrust
==================================================
Multi-tenant Ed25519 key generation, encryption, and management.

Features:
- Ed25519 keypair generation for institutions
- Private key encryption using master service key (AES-256-GCM)
- Secure key serialization to PEM format
- Key rotation support

Memory Optimized for 8GB RAM environments.
"""

import os
import base64
import hashlib
import secrets
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class InstitutionKeys:
    """Container for institution keypair data."""
    public_key_pem: str
    encrypted_private_key: str
    key_nonce: str
    institution_id: Optional[str] = None


class KMSError(Exception):
    """Base exception for KMS operations."""
    pass


class KeyGenerationError(KMSError):
    """Error during key generation."""
    pass


class KeyEncryptionError(KMSError):
    """Error during key encryption/decryption."""
    pass


class KeyNotFoundError(KMSError):
    """Key not found in storage."""
    pass


class KMSService:
    """
    Key Management System for multi-tenant institutions.
    
    Handles Ed25519 keypair generation, encryption, and storage
    with AES-256-GCM encryption for private keys.
    """
    
    # AES-256 key size in bytes
    AES_KEY_SIZE = 32
    # Nonce size for AES-GCM
    NONCE_SIZE = 12
    
    def __init__(self, supabase_url: Optional[str] = None, 
                 supabase_key: Optional[str] = None):
        """
        Initialize KMS with Supabase connection.
        
        Args:
            supabase_url: Supabase project URL
            supabase_key: Supabase service role key (used as master encryption key)
        """
        self._supabase_url = supabase_url or os.getenv("SUPABASE_URL")
        self._supabase_key = supabase_key or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        
        if not self._supabase_url or not self._supabase_key:
            raise KMSError("Supabase credentials not configured")
        
        # Derive master encryption key from service role key
        self._master_key = self._derive_master_key()
    
    def _derive_master_key(self) -> bytes:
        """
        Derives a 256-bit encryption key from the service role key.
        Uses HKDF-like derivation with SHA-256.
        
        Returns:
            32-byte key suitable for AES-256
        """
        # Use SHA-256 to derive a consistent key from the service role JWT
        key_material = self._supabase_key.encode('utf-8')
        # Add domain separation to prevent key reuse attacks
        domain = b"CertiTrust-KMS-v2"
        
        derived = hashlib.sha256(domain + key_material).digest()
        return derived
    
    def generate_keypair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """
        Generates a new Ed25519 keypair.
        
        Returns:
            Tuple of (private_key, public_key)
            
        Raises:
            KeyGenerationError: If key generation fails
        """
        try:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            return private_key, public_key
        except Exception as e:
            raise KeyGenerationError(f"Failed to generate keypair: {e}")
    
    def serialize_public_key(self, public_key: ed25519.Ed25519PublicKey) -> str:
        """
        Serializes public key to PEM format.
        
        Args:
            public_key: Ed25519 public key object
            
        Returns:
            PEM encoded public key string
        """
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('utf-8')
    
    def serialize_private_key(self, private_key: ed25519.Ed25519PrivateKey) -> bytes:
        """
        Serializes private key to PEM format.
        
        Args:
            private_key: Ed25519 private key object
            
        Returns:
            PEM encoded private key bytes
        """
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def encrypt_private_key(self, private_key: ed25519.Ed25519PrivateKey) -> Tuple[str, str]:
        """
        Encrypts private key using AES-256-GCM with the master key.
        
        Args:
            private_key: Ed25519 private key to encrypt
            
        Returns:
            Tuple of (encrypted_key_base64, nonce_base64)
            
        Raises:
            KeyEncryptionError: If encryption fails
        """
        try:
            # Serialize private key to PEM
            pem_bytes = self.serialize_private_key(private_key)
            
            # Generate random nonce
            nonce = secrets.token_bytes(self.NONCE_SIZE)
            
            # Encrypt with AES-256-GCM
            aesgcm = AESGCM(self._master_key)
            ciphertext = aesgcm.encrypt(nonce, pem_bytes, None)
            
            # Encode to base64 for storage
            encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')
            nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            
            return encrypted_b64, nonce_b64
            
        except Exception as e:
            raise KeyEncryptionError(f"Failed to encrypt private key: {e}")
    
    def decrypt_private_key(self, encrypted_key_b64: str, nonce_b64: str) -> ed25519.Ed25519PrivateKey:
        """
        Decrypts an encrypted private key.
        
        Args:
            encrypted_key_b64: Base64 encoded encrypted key
            nonce_b64: Base64 encoded nonce
            
        Returns:
            Ed25519PrivateKey object
            
        Raises:
            KeyEncryptionError: If decryption fails
        """
        try:
            # Decode from base64
            ciphertext = base64.b64decode(encrypted_key_b64)
            nonce = base64.b64decode(nonce_b64)
            
            # Decrypt with AES-256-GCM
            aesgcm = AESGCM(self._master_key)
            pem_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Load private key from PEM
            private_key = serialization.load_pem_private_key(pem_bytes, password=None)
            
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise KeyEncryptionError("Decrypted key is not Ed25519")
            
            return private_key
            
        except KeyEncryptionError:
            raise
        except Exception as e:
            raise KeyEncryptionError(f"Failed to decrypt private key: {e}")
    
    def load_public_key(self, public_key_pem: str) -> ed25519.Ed25519PublicKey:
        """
        Loads public key from PEM format.
        
        Args:
            public_key_pem: PEM encoded public key string
            
        Returns:
            Ed25519PublicKey object
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise ValueError("Not an Ed25519 public key")
            return public_key
        except Exception as e:
            raise KMSError(f"Failed to load public key: {e}")
    
    def create_institution_keys(self) -> InstitutionKeys:
        """
        Generates a complete set of keys for a new institution.
        
        Returns:
            InstitutionKeys object with public key PEM, encrypted private key, and nonce
        """
        # Generate keypair
        private_key, public_key = self.generate_keypair()
        
        # Serialize public key
        public_key_pem = self.serialize_public_key(public_key)
        
        # Encrypt private key
        encrypted_private_key, nonce = self.encrypt_private_key(private_key)
        
        return InstitutionKeys(
            public_key_pem=public_key_pem,
            encrypted_private_key=encrypted_private_key,
            key_nonce=nonce
        )


class InstitutionSigner:
    """
    Document signer for a specific institution.
    
    Loads institution's encrypted private key from Supabase
    and provides signing functionality.
    """
    
    def __init__(self, institution_id: str, kms: Optional[KMSService] = None,
                 supabase_url: Optional[str] = None, supabase_key: Optional[str] = None):
        """
        Initialize signer for a specific institution.
        
        Args:
            institution_id: UUID of the institution
            kms: Optional KMSService instance (created if not provided)
            supabase_url: Supabase project URL
            supabase_key: Supabase service role key
        """
        self._institution_id = institution_id
        self._supabase_url = supabase_url or os.getenv("SUPABASE_URL")
        self._supabase_key = supabase_key or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self._kms = kms or KMSService(self._supabase_url, self._supabase_key)
        
        # Lazy-loaded keys
        self._private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._public_key: Optional[ed25519.Ed25519PublicKey] = None
        self._institution_data: Optional[Dict[str, Any]] = None
    
    def _fetch_institution(self) -> Dict[str, Any]:
        """Fetches institution data from Supabase."""
        import httpx
        
        url = f"{self._supabase_url}/rest/v1/institutions"
        headers = {
            "apikey": self._supabase_key,
            "Authorization": f"Bearer {self._supabase_key}",
            "Content-Type": "application/json"
        }
        
        params = {
            "id": f"eq.{self._institution_id}",
            "select": "*"
        }
        
        try:
            response = httpx.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            if not data:
                raise KeyNotFoundError(f"Institution {self._institution_id} not found")
            
            return data[0]
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise KeyNotFoundError(f"Institution {self._institution_id} not found")
            raise KMSError(f"Failed to fetch institution: {e}")
        except Exception as e:
            raise KMSError(f"Failed to fetch institution: {e}")
    
    def _load_keys(self):
        """Loads and decrypts institution keys."""
        if self._private_key is not None:
            return
        
        self._institution_data = self._fetch_institution()
        
        # Decrypt private key
        encrypted_key = self._institution_data['encrypted_private_key']
        nonce = self._institution_data['key_nonce']
        
        self._private_key = self._kms.decrypt_private_key(encrypted_key, nonce)
        self._public_key = self._private_key.public_key()
    
    @property
    def institution_id(self) -> str:
        return self._institution_id
    
    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        """Returns the institution's public key."""
        self._load_keys()
        return self._public_key
    
    @property
    def public_key_pem(self) -> str:
        """Returns the institution's public key in PEM format."""
        self._load_keys()
        return self._institution_data['public_key_pem']
    
    def sign_document(self, data_hash: str) -> str:
        """
        Signs a document hash using the institution's private key.
        
        Args:
            data_hash: Hex string of the document hash (SHA-256)
            
        Returns:
            Base64 encoded Ed25519 signature
        """
        self._load_keys()
        
        # Sign the UTF-8 bytes of the hash string
        signature = self._private_key.sign(data_hash.encode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, data_hash: str, signature_b64: str) -> bool:
        """
        Verifies a signature using the institution's public key.
        
        Args:
            data_hash: Hex string of the document hash
            signature_b64: Base64 encoded signature
            
        Returns:
            True if valid, False otherwise
        """
        self._load_keys()
        
        try:
            signature = base64.b64decode(signature_b64)
            self._public_key.verify(signature, data_hash.encode('utf-8'))
            return True
        except Exception:
            return False


# Legacy compatibility - wraps the old DocumentSigner interface
class LegacyDocumentSigner:
    """
    Backward-compatible document signer that uses environment variable key.
    
    This is for legacy single-tenant mode or development.
    """
    
    def __init__(self):
        self._private_key = self._load_private_key()
        self._public_key = self._private_key.public_key()
    
    def _load_private_key(self) -> ed25519.Ed25519PrivateKey:
        """Loads the ISSUER_PRIVATE_KEY from environment variables."""
        key_b64 = os.getenv("ISSUER_PRIVATE_KEY")
        if key_b64:
            try:
                key_bytes = base64.b64decode(key_b64)
                
                # Try loading as raw bytes (32 bytes for Ed25519 seed)
                if len(key_bytes) == 32:
                    return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
                
                # Try loading as PEM
                key = serialization.load_pem_private_key(key_bytes, password=None)
                return key
            except Exception:
                pass
        
        print("WARNING: ISSUER_PRIVATE_KEY not found. Using temporary generated key.")
        return ed25519.Ed25519PrivateKey.generate()
    
    def sign_document(self, data_hash: str) -> str:
        """Signs the document hash using Ed25519."""
        signature = self._private_key.sign(data_hash.encode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, data_hash: str, signature_b64: str) -> bool:
        """Verifies the signature of a document hash."""
        try:
            signature = base64.b64decode(signature_b64)
            self._public_key.verify(signature, data_hash.encode('utf-8'))
            return True
        except Exception:
            return False
    
    def get_public_key_pem(self) -> str:
        """Returns the public key in PEM format."""
        pem_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode('utf-8')
