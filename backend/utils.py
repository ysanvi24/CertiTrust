"""
Utility Functions for CertiTrust
================================
Memory-optimized utilities for 8GB RAM environments.

Features:
- Chunked file hashing (64KB buffers)
- Generator-based processing
- Memory-efficient file operations
"""

import hashlib
import os
from typing import Union, Generator, BinaryIO, Optional, List
from pathlib import Path
from contextlib import contextmanager


# 64KB chunk size - optimal for most file systems and memory usage
CHUNK_SIZE = 65536

# Maximum file size for in-memory processing (50MB)
MAX_MEMORY_FILE_SIZE = 50 * 1024 * 1024


def secure_hash(file_path: Union[str, Path]) -> str:
    """
    Calculates the SHA-256 of a file in 64KB chunks.
    
    Memory-efficient implementation that never loads the entire file.

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


def hash_bytes(data: bytes) -> str:
    """
    Calculates SHA-256 hash of bytes.
    
    Args:
        data: Bytes to hash
        
    Returns:
        Hex digest of the SHA-256 hash
    """
    return hashlib.sha256(data).hexdigest()


def hash_string(data: str) -> str:
    """
    Calculates SHA-256 hash of a string.
    
    Args:
        data: String to hash
        
    Returns:
        Hex digest of the SHA-256 hash
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def chunked_file_reader(
    file_path: Union[str, Path],
    chunk_size: int = CHUNK_SIZE
) -> Generator[bytes, None, None]:
    """
    Generator that yields file contents in chunks.
    
    Memory-efficient for processing large files.
    
    Args:
        file_path: Path to the file
        chunk_size: Size of each chunk in bytes
        
    Yields:
        Bytes chunks of the file
    """
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def chunked_hash_update(
    hasher: "hashlib._Hash",
    file_path: Union[str, Path],
    chunk_size: int = CHUNK_SIZE
) -> None:
    """
    Updates a hashlib hasher with file contents in chunks.
    
    Args:
        hasher: Hashlib hash object
        file_path: Path to the file
        chunk_size: Size of each chunk in bytes
    """
    for chunk in chunked_file_reader(file_path, chunk_size):
        hasher.update(chunk)


def hash_stream(
    stream: BinaryIO,
    chunk_size: int = CHUNK_SIZE
) -> str:
    """
    Calculates SHA-256 hash from a binary stream.
    
    Useful for hashing uploaded files without saving to disk.
    
    Args:
        stream: Binary file-like object
        chunk_size: Size of each chunk
        
    Returns:
        Hex digest of SHA-256 hash
    """
    sha256_hash = hashlib.sha256()
    
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        sha256_hash.update(chunk)
    
    # Reset stream position if possible
    if hasattr(stream, 'seek'):
        stream.seek(0)
    
    return sha256_hash.hexdigest()


def compare_hashes(hash1: str, hash2: str) -> bool:
    """
    Constant-time comparison of two hashes to prevent timing attacks.
    
    Args:
        hash1: First hash (hex string)
        hash2: Second hash (hex string)
        
    Returns:
        True if hashes match
    """
    import hmac
    return hmac.compare_digest(hash1.lower(), hash2.lower())


@contextmanager
def temp_file_context(prefix: str = "certitrust_", suffix: str = ".tmp"):
    """
    Context manager for temporary file handling with automatic cleanup.
    
    Args:
        prefix: Temp file prefix
        suffix: Temp file suffix
        
    Yields:
        Path to temporary file
    """
    import tempfile
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    try:
        os.close(fd)
        yield Path(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def get_file_size(file_path: Union[str, Path]) -> int:
    """
    Gets file size without reading the file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        File size in bytes
    """
    return os.path.getsize(file_path)


def is_safe_for_memory(file_path: Union[str, Path], threshold: int = MAX_MEMORY_FILE_SIZE) -> bool:
    """
    Checks if a file is small enough to load into memory safely.
    
    Args:
        file_path: Path to the file
        threshold: Maximum safe size in bytes
        
    Returns:
        True if file is safe to load into memory
    """
    return get_file_size(file_path) <= threshold


def split_file_for_parallel_hash(
    file_path: Union[str, Path],
    num_parts: int = 4
) -> List[tuple]:
    """
    Splits a file into ranges for parallel hashing.
    
    Note: Actual parallel hashing requires multiprocessing.
    This function just calculates the byte ranges.
    
    Args:
        file_path: Path to the file
        num_parts: Number of parts to split into
        
    Returns:
        List of (start_byte, end_byte) tuples
    """
    file_size = get_file_size(file_path)
    part_size = file_size // num_parts
    
    ranges = []
    for i in range(num_parts):
        start = i * part_size
        end = (i + 1) * part_size if i < num_parts - 1 else file_size
        ranges.append((start, end))
    
    return ranges


def hash_file_range(
    file_path: Union[str, Path],
    start: int,
    end: int,
    chunk_size: int = CHUNK_SIZE
) -> str:
    """
    Hashes a specific byte range of a file.
    
    Args:
        file_path: Path to the file
        start: Start byte position
        end: End byte position
        chunk_size: Chunk size for reading
        
    Returns:
        SHA-256 hex digest of the range
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        f.seek(start)
        remaining = end - start
        
        while remaining > 0:
            read_size = min(chunk_size, remaining)
            chunk = f.read(read_size)
            if not chunk:
                break
            sha256_hash.update(chunk)
            remaining -= len(chunk)
    
    return sha256_hash.hexdigest()


def validate_hash_format(hash_str: str) -> bool:
    """
    Validates that a string is a valid SHA-256 hex hash.
    
    Args:
        hash_str: String to validate
        
    Returns:
        True if valid SHA-256 hash format
    """
    if not hash_str or len(hash_str) != 64:
        return False
    
    try:
        int(hash_str, 16)
        return True
    except ValueError:
        return False


def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """
    Masks sensitive data for logging purposes.
    
    Args:
        data: Sensitive string to mask
        visible_chars: Number of characters to show at end
        
    Returns:
        Masked string (e.g., "****1234")
    """
    if not data:
        return ""
    
    if len(data) <= visible_chars:
        return "*" * len(data)
    
    return "*" * (len(data) - visible_chars) + data[-visible_chars:]


# ============================================================
# Trust Score Calculation
# ============================================================

class TrustScoreWeights:
    """
    Weights for Trust Score calculation.
    
    Formula:
    TS = (0.4 × Crypto) + (0.3 × ELA) + (0.2 × AI) + (0.1 × Metadata)
    
    Where each component is normalized to 0.0-1.0:
    - Crypto: 1.0 if signature valid, 0.0 otherwise
    - ELA: 1.0 - tamper_score (inverted: lower tamper = higher trust)
    - AI: 1.0 - manipulation_score (inverted)
    - Metadata: 1.0 - anomaly_score (inverted)
    """
    CRYPTOGRAPHIC_SIGNATURE = 0.4
    ELA_TAMPER_SCORE = 0.3
    AI_CLASSIFICATION = 0.2
    METADATA_ANOMALIES = 0.1


def calculate_trust_score(
    crypto_valid: bool,
    ela_tamper_score: float = 0.0,
    ai_manipulation_score: float = 0.0,
    metadata_anomaly_score: float = 0.0,
    weights: Optional[TrustScoreWeights] = None
) -> dict:
    """
    Calculates weighted Trust Score for document verification.
    
    Mathematical Model:
    TS = (0.4 × Crypto) + (0.3 × ELA) + (0.2 × AI) + (0.1 × Metadata)
    
    Args:
        crypto_valid: True if cryptographic signature is valid
        ela_tamper_score: ELA tamper score (0.0-1.0, higher = more tampering)
        ai_manipulation_score: AI manipulation score (0.0-1.0, higher = more manipulation)
        metadata_anomaly_score: Metadata anomaly score (0.0-1.0, higher = more anomalies)
        weights: Optional custom weights
        
    Returns:
        Dictionary containing:
        - trust_score: Final weighted score (0.0-1.0, higher = more trustworthy)
        - components: Individual component scores
        - grade: Letter grade (A-F)
        - verdict: Human-readable verdict
    """
    if weights is None:
        weights = TrustScoreWeights()
    
    # Normalize component scores (invert forensic scores since lower = better)
    crypto_score = 1.0 if crypto_valid else 0.0
    ela_score = 1.0 - min(1.0, max(0.0, ela_tamper_score))
    ai_score = 1.0 - min(1.0, max(0.0, ai_manipulation_score))
    metadata_score = 1.0 - min(1.0, max(0.0, metadata_anomaly_score))
    
    # Calculate weighted Trust Score
    trust_score = (
        (weights.CRYPTOGRAPHIC_SIGNATURE * crypto_score) +
        (weights.ELA_TAMPER_SCORE * ela_score) +
        (weights.AI_CLASSIFICATION * ai_score) +
        (weights.METADATA_ANOMALIES * metadata_score)
    )
    
    # Clamp to 0.0-1.0
    trust_score = min(1.0, max(0.0, trust_score))
    
    # Determine grade
    if trust_score >= 0.9:
        grade = "A"
        verdict = "Highly Trusted - Document passes all verification checks"
    elif trust_score >= 0.75:
        grade = "B"
        verdict = "Trusted - Document passes primary checks with minor concerns"
    elif trust_score >= 0.6:
        grade = "C"
        verdict = "Conditional - Document has some verification concerns"
    elif trust_score >= 0.4:
        grade = "D"
        verdict = "Suspicious - Document fails multiple verification checks"
    else:
        grade = "F"
        verdict = "Untrustworthy - Document fails critical verification checks"
    
    return {
        "trust_score": round(trust_score, 4),
        "trust_score_percent": round(trust_score * 100, 2),
        "grade": grade,
        "verdict": verdict,
        "components": {
            "cryptographic_signature": {
                "score": round(crypto_score, 4),
                "weight": weights.CRYPTOGRAPHIC_SIGNATURE,
                "weighted_contribution": round(crypto_score * weights.CRYPTOGRAPHIC_SIGNATURE, 4),
                "valid": crypto_valid
            },
            "ela_analysis": {
                "score": round(ela_score, 4),
                "weight": weights.ELA_TAMPER_SCORE,
                "weighted_contribution": round(ela_score * weights.ELA_TAMPER_SCORE, 4),
                "tamper_score": round(ela_tamper_score, 4)
            },
            "ai_detection": {
                "score": round(ai_score, 4),
                "weight": weights.AI_CLASSIFICATION,
                "weighted_contribution": round(ai_score * weights.AI_CLASSIFICATION, 4),
                "manipulation_score": round(ai_manipulation_score, 4)
            },
            "metadata_analysis": {
                "score": round(metadata_score, 4),
                "weight": weights.METADATA_ANOMALIES,
                "weighted_contribution": round(metadata_score * weights.METADATA_ANOMALIES, 4),
                "anomaly_score": round(metadata_anomaly_score, 4)
            }
        }
    }


def quick_trust_score(
    crypto_valid: bool,
    forensic_report: Optional[dict] = None
) -> dict:
    """
    Quick Trust Score calculation from forensic report.
    
    Args:
        crypto_valid: True if cryptographic signature is valid
        forensic_report: Optional forensic report dictionary
        
    Returns:
        Trust score result dictionary
    """
    ela_score = 0.0
    ai_score = 0.0
    metadata_score = 0.0
    
    if forensic_report:
        # Extract ELA tamper score
        ela_result = forensic_report.get("ela_result")
        if ela_result:
            ela_score = ela_result.get("tamper_score", 0.0)
        
        # Extract AI manipulation score
        ai_result = forensic_report.get("ai_detection_result")
        if ai_result:
            scores = ai_result.get("scores", {})
            # Use AI detector artificial score or ViT fake score
            ai_score = max(
                scores.get("ai_detector_artificial", 0.0),
                scores.get("vit_fake", 0.0)
            )
        
        # Extract metadata anomaly score
        metadata_result = forensic_report.get("metadata_result")
        if metadata_result:
            metadata_score = metadata_result.get("anomaly_score", 0.0)
    
    return calculate_trust_score(
        crypto_valid=crypto_valid,
        ela_tamper_score=ela_score,
        ai_manipulation_score=ai_score,
        metadata_anomaly_score=metadata_score
    )
