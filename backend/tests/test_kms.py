"""
Test Suite for KMS (Key Management System) Service
===================================================
Tests for Ed25519 key generation, encryption, and decryption.
"""

import pytest
import os
import base64
from unittest.mock import patch, MagicMock


class TestKMSService:
    """Tests for KMSService class."""
    
    def test_initialization_with_env_vars(self):
        """Test KMS initializes with environment variables."""
        # Set specific env vars for this test
        test_url = 'http://test.supabase.co'
        test_key = 'test_key_' + 'x' * 200
        
        with patch.dict(os.environ, {'SUPABASE_URL': test_url, 'SUPABASE_SERVICE_ROLE_KEY': test_key}):
            from backend.services.kms import KMSService
            kms = KMSService()
            assert kms._supabase_url == test_url
            assert kms._master_key is not None
            assert len(kms._master_key) == 32  # AES-256 key
    
    def test_initialization_with_explicit_params(self):
        """Test KMS initializes with explicit parameters."""
        from backend.services.kms import KMSService
        kms = KMSService(
            supabase_url='http://custom.url',
            supabase_key='custom_key'
        )
        assert kms._supabase_url == 'http://custom.url'
    
    def test_initialization_fails_without_credentials(self):
        """Test KMS raises error without credentials."""
        from backend.services.kms import KMSService, KMSError
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(KMSError):
                KMSService(supabase_url=None, supabase_key=None)
    
    def test_master_key_derivation_deterministic(self):
        """Test that master key derivation is deterministic."""
        from backend.services.kms import KMSService
        with patch.dict(os.environ, {'SUPABASE_URL': 'http://test.co', 'SUPABASE_SERVICE_ROLE_KEY': 'test_key'}):
            kms1 = KMSService()
            kms2 = KMSService()
            assert kms1._master_key == kms2._master_key
    
    def test_master_key_derivation_changes_with_key(self):
        """Test that different service keys produce different master keys."""
        from backend.services.kms import KMSService
        kms1 = KMSService(supabase_url='http://test.co', supabase_key='key1')
        kms2 = KMSService(supabase_url='http://test.co', supabase_key='key2')
        assert kms1._master_key != kms2._master_key


class TestKeyGeneration:
    """Tests for keypair generation."""
    
    def test_generate_keypair(self):
        """Test Ed25519 keypair generation."""
        from backend.services.kms import KMSService
        from cryptography.hazmat.primitives.asymmetric import ed25519
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        private_key, public_key = kms.generate_keypair()
        
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)
        assert isinstance(public_key, ed25519.Ed25519PublicKey)
    
    def test_keypair_uniqueness(self):
        """Test that each generation produces unique keys."""
        from backend.services.kms import KMSService
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        
        pairs = [kms.generate_keypair() for _ in range(5)]
        private_keys = [kms.serialize_private_key(p[0]) for p in pairs]
        
        # All private keys should be unique
        assert len(set(private_keys)) == 5
    
    def test_public_key_serialization(self):
        """Test public key serialization to PEM."""
        from backend.services.kms import KMSService
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        _, public_key = kms.generate_keypair()
        
        pem = kms.serialize_public_key(public_key)
        
        assert isinstance(pem, str)
        assert '-----BEGIN PUBLIC KEY-----' in pem
        assert '-----END PUBLIC KEY-----' in pem
    
    def test_private_key_serialization(self):
        """Test private key serialization to PEM bytes."""
        from backend.services.kms import KMSService
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        private_key, _ = kms.generate_keypair()
        
        pem_bytes = kms.serialize_private_key(private_key)
        
        assert isinstance(pem_bytes, bytes)
        assert b'-----BEGIN PRIVATE KEY-----' in pem_bytes


class TestKeyEncryption:
    """Tests for key encryption and decryption."""
    
    def test_encrypt_private_key(self):
        """Test private key encryption produces valid output."""
        from backend.services.kms import KMSService
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        private_key, _ = kms.generate_keypair()
        
        encrypted, nonce = kms.encrypt_private_key(private_key)
        
        # Should be base64 encoded strings
        assert isinstance(encrypted, str)
        assert isinstance(nonce, str)
        
        # Should be decodable
        base64.b64decode(encrypted)
        base64.b64decode(nonce)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption followed by decryption returns original key."""
        from backend.services.kms import KMSService
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        private_key, _ = kms.generate_keypair()
        
        # Get original key bytes for comparison
        original_bytes = kms.serialize_private_key(private_key)
        
        # Encrypt then decrypt
        encrypted, nonce = kms.encrypt_private_key(private_key)
        decrypted_key = kms.decrypt_private_key(encrypted, nonce)
        
        # Compare serialized forms
        decrypted_bytes = kms.serialize_private_key(decrypted_key)
        assert original_bytes == decrypted_bytes
    
    def test_decrypt_with_wrong_nonce_fails(self):
        """Test decryption fails with incorrect nonce."""
        from backend.services.kms import KMSService, KeyEncryptionError
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        private_key, _ = kms.generate_keypair()
        
        encrypted, _ = kms.encrypt_private_key(private_key)
        
        # Generate different nonce
        wrong_nonce = base64.b64encode(b'wrong_nonce1').decode('utf-8')
        
        with pytest.raises(KeyEncryptionError):
            kms.decrypt_private_key(encrypted, wrong_nonce)
    
    def test_decrypt_with_corrupted_data_fails(self):
        """Test decryption fails with corrupted ciphertext."""
        from backend.services.kms import KMSService, KeyEncryptionError
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        private_key, _ = kms.generate_keypair()
        
        _, nonce = kms.encrypt_private_key(private_key)
        corrupted = base64.b64encode(b'corrupted_data').decode('utf-8')
        
        with pytest.raises(KeyEncryptionError):
            kms.decrypt_private_key(corrupted, nonce)


class TestInstitutionKeys:
    """Tests for institution key creation."""
    
    def test_create_institution_keys(self):
        """Test complete institution keys creation."""
        from backend.services.kms import KMSService, InstitutionKeys
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        keys = kms.create_institution_keys()
        
        assert isinstance(keys, InstitutionKeys)
        assert keys.public_key_pem is not None
        assert keys.encrypted_private_key is not None
        assert keys.key_nonce is not None
        
        # Verify public key format
        assert '-----BEGIN PUBLIC KEY-----' in keys.public_key_pem
    
    def test_institution_keys_are_unique(self):
        """Test each call produces unique keys."""
        from backend.services.kms import KMSService
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        
        keys1 = kms.create_institution_keys()
        keys2 = kms.create_institution_keys()
        
        assert keys1.public_key_pem != keys2.public_key_pem
        assert keys1.encrypted_private_key != keys2.encrypted_private_key


class TestLegacyDocumentSigner:
    """Tests for legacy document signer."""
    
    def test_sign_and_verify(self):
        """Test signing and verifying with legacy signer."""
        from backend.services.kms import LegacyDocumentSigner
        
        signer = LegacyDocumentSigner()
        
        data_hash = "abc123def456"
        signature = signer.sign_document(data_hash)
        
        assert isinstance(signature, str)
        assert signer.verify_signature(data_hash, signature)
    
    def test_verify_fails_with_wrong_hash(self):
        """Test verification fails with different hash."""
        from backend.services.kms import LegacyDocumentSigner
        
        signer = LegacyDocumentSigner()
        
        signature = signer.sign_document("original_hash")
        assert not signer.verify_signature("different_hash", signature)
    
    def test_verify_fails_with_wrong_signature(self):
        """Test verification fails with invalid signature."""
        from backend.services.kms import LegacyDocumentSigner
        
        signer = LegacyDocumentSigner()
        
        wrong_sig = base64.b64encode(b'wrong_signature').decode('utf-8')
        assert not signer.verify_signature("some_hash", wrong_sig)
    
    def test_get_public_key_pem(self):
        """Test getting public key in PEM format."""
        from backend.services.kms import LegacyDocumentSigner
        
        signer = LegacyDocumentSigner()
        
        pem = signer.get_public_key_pem()
        
        assert '-----BEGIN PUBLIC KEY-----' in pem


class TestKeyLoading:
    """Tests for loading public keys."""
    
    def test_load_public_key_from_pem(self):
        """Test loading a public key from PEM string."""
        from backend.services.kms import KMSService
        from cryptography.hazmat.primitives.asymmetric import ed25519
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        _, public_key = kms.generate_keypair()
        pem = kms.serialize_public_key(public_key)
        
        loaded = kms.load_public_key(pem)
        
        assert isinstance(loaded, ed25519.Ed25519PublicKey)
    
    def test_load_public_key_invalid_pem_fails(self):
        """Test loading invalid PEM fails gracefully."""
        from backend.services.kms import KMSService, KMSError
        
        kms = KMSService(supabase_url='http://test.co', supabase_key='test_key')
        
        with pytest.raises(KMSError):
            kms.load_public_key("not a valid PEM")
