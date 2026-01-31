import hashlib
from typing import Union
from pathlib import Path

# 64KB chunk size
CHUNK_SIZE = 65536

def secure_hash(file_path: Union[str, Path]) -> str:
    """
    Calculates the SHA-256 of a file in 64KB chunks.

    Args:
        file_path: Path to the file.

    Returns:
        Hex digest of the SHA-256 hash.
    """
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 64K
        for byte_block in iter(lambda: f.read(CHUNK_SIZE), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()
