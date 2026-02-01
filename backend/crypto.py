import os
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class DocumentSigner:
    def __init__(self):
        self._private_key = self._load_private_key()
        self._public_key = self._private_key.public_key()

    def _load_private_key(self) -> ed25519.Ed25519PrivateKey:
        """
        Loads the ISSUER_PRIVATE_KEY from environment variables.
        If not present, generates a new one (for development/demo purposes).
        """
        key_b64 = os.getenv("ISSUER_PRIVATE_KEY")
        if key_b64:
            try:
                # Assume base64 encoded private key bytes
                key_bytes = base64.b64decode(key_b64)

                # Try loading as raw bytes (32 bytes for Ed25519 seed)
                if len(key_bytes) == 32:
                    return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)

                # Try loading as PEM
                key = serialization.load_pem_private_key(key_bytes, password=None)
                print("Successfully loaded ISSUER_PRIVATE_KEY from environment.")
                return key
            except Exception as e:
                print(f"Error loading key from env: {e}")
                pass

        print("WARNING: ISSUER_PRIVATE_KEY not found or invalid. Using a temporary generated key.")
        return ed25519.Ed25519PrivateKey.generate()

    def sign_document(self, data_hash: str) -> str:
        """
        Signs the document hash using Ed25519.
        Args:
            data_hash: The hex string of the SHA-256 hash.
        Returns:
            Base64 encoded signature.
        """
        # Sign the utf-8 bytes of the hash string
        signature = self._private_key.sign(data_hash.encode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, data_hash: str, signature_b64: str) -> bool:
        """
        Verifies the signature of a document hash.
        Args:
            data_hash: The hex string of the SHA-256 hash.
            signature_b64: Base64 encoded signature.
        Returns:
            True if valid, False otherwise.
        """
        try:
            signature = base64.b64decode(signature_b64)
            self._public_key.verify(signature, data_hash.encode('utf-8'))
            return True
        except Exception:
            return False
