import hashlib
from backend.utils import secure_hash, CHUNK_SIZE

def test_secure_hash_consistency(temp_file):
    # Calculate hash manually
    content = temp_file.read_bytes()
    expected_hash = hashlib.sha256(content).hexdigest()

    calculated_hash = secure_hash(temp_file)
    assert calculated_hash == expected_hash

def test_large_file_hashing(tmp_path):
    # Create a file larger than CHUNK_SIZE (64KB)
    large_file = tmp_path / "large.bin"
    size = CHUNK_SIZE * 2 + 100
    content = b"a" * size
    large_file.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()
    calculated_hash = secure_hash(large_file)

    assert calculated_hash == expected_hash
