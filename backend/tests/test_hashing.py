"""
Test Suite for Hashing Utilities
================================
Tests for memory-efficient chunked SHA-256 hashing.
"""

import hashlib
import os
import pytest
from io import BytesIO

from backend.utils import (
    secure_hash, hash_bytes, hash_string, chunked_file_reader,
    hash_stream, compare_hashes, validate_hash_format,
    hash_file_range, CHUNK_SIZE, is_safe_for_memory,
    mask_sensitive_data
)


class TestSecureHash:
    """Tests for the secure_hash function."""
    
    def test_secure_hash_consistency(self, temp_file):
        """Test that hash is consistent with standard hashlib."""
        content = temp_file.read_bytes()
        expected_hash = hashlib.sha256(content).hexdigest()

        calculated_hash = secure_hash(temp_file)
        assert calculated_hash == expected_hash

    def test_large_file_hashing(self, tmp_path):
        """Test hashing a file larger than CHUNK_SIZE (64KB)."""
        large_file = tmp_path / "large.bin"
        size = CHUNK_SIZE * 2 + 100
        content = b"a" * size
        large_file.write_bytes(content)

        expected_hash = hashlib.sha256(content).hexdigest()
        calculated_hash = secure_hash(large_file)

        assert calculated_hash == expected_hash
    
    def test_empty_file_hashing(self, tmp_path):
        """Test hashing an empty file."""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_bytes(b"")
        
        expected = hashlib.sha256(b"").hexdigest()
        assert secure_hash(empty_file) == expected
    
    def test_hash_different_for_different_content(self, tmp_path):
        """Test that different content produces different hashes."""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        
        file1.write_bytes(b"content1")
        file2.write_bytes(b"content2")
        
        assert secure_hash(file1) != secure_hash(file2)
    
    def test_single_bit_change_detection(self, tmp_path):
        """Test that a single bit change is detected."""
        file1 = tmp_path / "original.bin"
        file2 = tmp_path / "modified.bin"
        
        # Create two files differing by one bit
        content = b"Hello World!"
        file1.write_bytes(content)
        
        # Flip one bit
        modified = bytearray(content)
        modified[0] ^= 1  # Flip lowest bit of first byte
        file2.write_bytes(bytes(modified))
        
        hash1 = secure_hash(file1)
        hash2 = secure_hash(file2)
        
        assert hash1 != hash2


class TestHashBytes:
    """Tests for hash_bytes function."""
    
    def test_hash_bytes_basic(self):
        """Test basic bytes hashing."""
        data = b"test data"
        result = hash_bytes(data)
        
        assert result == hashlib.sha256(data).hexdigest()
    
    def test_hash_bytes_empty(self):
        """Test hashing empty bytes."""
        result = hash_bytes(b"")
        assert result == hashlib.sha256(b"").hexdigest()


class TestHashString:
    """Tests for hash_string function."""
    
    def test_hash_string_basic(self):
        """Test basic string hashing."""
        data = "test string"
        result = hash_string(data)
        
        expected = hashlib.sha256(data.encode('utf-8')).hexdigest()
        assert result == expected
    
    def test_hash_string_unicode(self):
        """Test Unicode string hashing."""
        data = "Hello 世界 🌍"
        result = hash_string(data)
        
        assert len(result) == 64  # Valid SHA-256 hash


class TestChunkedFileReader:
    """Tests for the chunked file reader generator."""
    
    def test_chunked_reader_yields_correct_chunks(self, tmp_path):
        """Test that chunked reader yields correct chunks."""
        test_file = tmp_path / "test.bin"
        content = b"x" * (CHUNK_SIZE * 2 + 100)
        test_file.write_bytes(content)
        
        chunks = list(chunked_file_reader(test_file))
        
        # Should have 3 chunks
        assert len(chunks) == 3
        assert len(chunks[0]) == CHUNK_SIZE
        assert len(chunks[1]) == CHUNK_SIZE
        assert len(chunks[2]) == 100
    
    def test_chunked_reader_small_file(self, tmp_path):
        """Test chunked reader with file smaller than chunk size."""
        test_file = tmp_path / "small.txt"
        test_file.write_bytes(b"small content")
        
        chunks = list(chunked_file_reader(test_file))
        
        assert len(chunks) == 1
        assert chunks[0] == b"small content"


class TestHashStream:
    """Tests for stream hashing."""
    
    def test_hash_stream_basic(self):
        """Test hashing from a stream."""
        content = b"stream content"
        stream = BytesIO(content)
        
        result = hash_stream(stream)
        expected = hashlib.sha256(content).hexdigest()
        
        assert result == expected
    
    def test_hash_stream_resets_position(self):
        """Test that stream position is reset after hashing."""
        content = b"test content"
        stream = BytesIO(content)
        
        hash_stream(stream)
        
        # Should be able to read from beginning
        assert stream.read() == content


class TestCompareHashes:
    """Tests for constant-time hash comparison."""
    
    def test_compare_equal_hashes(self):
        """Test comparing equal hashes."""
        hash1 = "abc123"
        hash2 = "abc123"
        
        assert compare_hashes(hash1, hash2) is True
    
    def test_compare_different_hashes(self):
        """Test comparing different hashes."""
        hash1 = "abc123"
        hash2 = "xyz789"
        
        assert compare_hashes(hash1, hash2) is False
    
    def test_compare_case_insensitive(self):
        """Test that comparison is case-insensitive."""
        hash1 = "ABC123"
        hash2 = "abc123"
        
        assert compare_hashes(hash1, hash2) is True


class TestValidateHashFormat:
    """Tests for hash format validation."""
    
    def test_valid_sha256_hash(self):
        """Test validation of valid SHA-256 hash."""
        valid_hash = "a" * 64
        assert validate_hash_format(valid_hash) is True
    
    def test_invalid_length(self):
        """Test validation fails for wrong length."""
        assert validate_hash_format("abc123") is False
        assert validate_hash_format("a" * 63) is False
        assert validate_hash_format("a" * 65) is False
    
    def test_invalid_characters(self):
        """Test validation fails for non-hex characters."""
        invalid_hash = "g" * 64  # 'g' is not valid hex
        assert validate_hash_format(invalid_hash) is False
    
    def test_empty_string(self):
        """Test validation fails for empty string."""
        assert validate_hash_format("") is False
    
    def test_none_value(self):
        """Test validation fails for None."""
        assert validate_hash_format(None) is False


class TestHashFileRange:
    """Tests for hashing specific byte ranges."""
    
    def test_hash_file_range_full(self, tmp_path):
        """Test hashing full file via range."""
        test_file = tmp_path / "test.bin"
        content = b"full file content"
        test_file.write_bytes(content)
        
        result = hash_file_range(test_file, 0, len(content))
        expected = hashlib.sha256(content).hexdigest()
        
        assert result == expected
    
    def test_hash_file_range_partial(self, tmp_path):
        """Test hashing partial file."""
        test_file = tmp_path / "test.bin"
        content = b"0123456789"
        test_file.write_bytes(content)
        
        # Hash bytes 2-6
        result = hash_file_range(test_file, 2, 6)
        expected = hashlib.sha256(b"2345").hexdigest()
        
        assert result == expected


class TestIsSafeForMemory:
    """Tests for memory safety check."""
    
    def test_small_file_safe(self, tmp_path):
        """Test that small files are marked safe."""
        small_file = tmp_path / "small.txt"
        small_file.write_bytes(b"x" * 1000)
        
        assert is_safe_for_memory(small_file) is True
    
    def test_custom_threshold(self, tmp_path):
        """Test custom threshold."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"x" * 1000)
        
        assert is_safe_for_memory(test_file, threshold=500) is False
        assert is_safe_for_memory(test_file, threshold=2000) is True


class TestMaskSensitiveData:
    """Tests for data masking utility."""
    
    def test_mask_basic(self):
        """Test basic masking."""
        result = mask_sensitive_data("1234567890", visible_chars=4)
        assert result == "******7890"
    
    def test_mask_short_string(self):
        """Test masking string shorter than visible chars."""
        result = mask_sensitive_data("abc", visible_chars=4)
        assert result == "***"
    
    def test_mask_empty_string(self):
        """Test masking empty string."""
        result = mask_sensitive_data("")
        assert result == ""


@pytest.mark.memory
class TestMemoryEfficiency:
    """Tests for memory-efficient operations."""
    
    def test_large_file_does_not_spike_memory(self, large_file):
        """Test that hashing large files uses bounded memory."""
        import tracemalloc
        
        tracemalloc.start()
        
        # Hash the large file
        secure_hash(large_file)
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Peak memory should not exceed 2MB (well under the 64KB chunk + overhead)
        # This is generous to account for Python overhead
        assert peak < 2 * 1024 * 1024, f"Peak memory usage too high: {peak / 1024 / 1024:.2f}MB"
