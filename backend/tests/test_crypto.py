import pytest
import os
import base64
from backend.crypto import DocumentSigner

def test_signer_generates_key_if_missing():
    # Ensure env is empty for this test
    old_key = os.environ.get("ISSUER_PRIVATE_KEY")
    if old_key:
        del os.environ["ISSUER_PRIVATE_KEY"]

    try:
        signer = DocumentSigner()
        # It should have generated a key
        assert signer._private_key is not None
    finally:
        if old_key:
            os.environ["ISSUER_PRIVATE_KEY"] = old_key

def test_sign_and_verify():
    signer = DocumentSigner()
    data_hash = "1234567890abcdef"

    signature = signer.sign_document(data_hash)
    assert signature is not None
    assert isinstance(signature, str)

    # Verify
    assert signer.verify_signature(data_hash, signature) is True

def test_verify_fails_on_wrong_data():
    signer = DocumentSigner()
    data_hash = "1234567890abcdef"
    wrong_hash = "0000000000000000"

    signature = signer.sign_document(data_hash)

    assert signer.verify_signature(wrong_hash, signature) is False
