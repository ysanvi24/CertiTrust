import os
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Global variable to cache the key if generated, so it stays consistent during the process runtime
_TEMP_KEY = None

def get_issuer_private_key() -> ed25519.Ed25519PrivateKey:
    """
    Loads the ISSUER_PRIVATE_KEY from environment variables.
    If not present, generates a new one (for development/demo purposes).
    """
    global _TEMP_KEY
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
            # Fallthrough to generate
            pass

    if _TEMP_KEY:
        return _TEMP_KEY

    print("WARNING: ISSUER_PRIVATE_KEY not found or invalid. Using a temporary generated key.")
    _TEMP_KEY = ed25519.Ed25519PrivateKey.generate()
    return _TEMP_KEY

def sign_hash(data_hash: str) -> str:
    """
    Signs the document hash using Ed25519.

    Args:
        data_hash: The hex string of the SHA-256 hash.

    Returns:
        Base64 encoded signature.
    """
    private_key = get_issuer_private_key()

    # Sign the utf-8 bytes of the hash string
    signature = private_key.sign(data_hash.encode('utf-8'))
    return base64.b64encode(signature).decode('utf-8')
