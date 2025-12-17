"""
Unit tests for the hash module
"""

import unittest
import sys
import os
import tempfile

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.hash import hash_file, verify_integrity


class TestHashModule(unittest.TestCase):
    """Test cases for file hashing and integrity verification functions"""

    def setUp(self):
        """Create temporary files for testing"""
        # Create a temporary file with known content
        self.temp_file1 = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.temp_file1.write("Test content for hashing")
        self.temp_file1.close()

        # Create an identical file
        self.temp_file2 = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.temp_file2.write("Test content for hashing")
        self.temp_file2.close()

        # Create a different file
        self.temp_file3 = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.temp_file3.write("Different content")
        self.temp_file3.close()

    def tearDown(self):
        """Clean up temporary files"""
        os.unlink(self.temp_file1.name)
        os.unlink(self.temp_file2.name)
        os.unlink(self.temp_file3.name)

    def test_hash_file_returns_string(self):
        """Test that hash_file returns a string"""
        result = hash_file(self.temp_file1.name)
        self.assertIsInstance(result, str)

    def test_hash_file_returns_hex(self):
        """Test that hash_file returns hexadecimal string"""
        result = hash_file(self.temp_file1.name)
        # SHA-256 produces 64 character hex string
        self.assertEqual(len(result), 64)
        # Check that all characters are hexadecimal
        self.assertTrue(all(c in '0123456789abcdef' for c in result))

    def test_hash_file_consistent(self):
        """Test that hashing the same file produces the same hash"""
        hash1 = hash_file(self.temp_file1.name)
        hash2 = hash_file(self.temp_file1.name)
        self.assertEqual(hash1, hash2)

    def test_hash_file_different_files(self):
        """Test that different files produce different hashes"""
        hash1 = hash_file(self.temp_file1.name)
        hash3 = hash_file(self.temp_file3.name)
        self.assertNotEqual(hash1, hash3)

    def test_hash_file_nonexistent(self):
        """Test that hashing non-existent file raises FileNotFoundError"""
        with self.assertRaises(FileNotFoundError):
            hash_file("nonexistent_file.txt")

    def test_verify_integrity_identical_files(self):
        """Test that verify_integrity returns True for identical files"""
        result = verify_integrity(self.temp_file1.name, self.temp_file2.name)
        self.assertTrue(result)

    def test_verify_integrity_different_files(self):
        """Test that verify_integrity returns False for different files"""
        result = verify_integrity(self.temp_file1.name, self.temp_file3.name)
        self.assertFalse(result)

    def test_verify_integrity_same_file(self):
        """Test that verify_integrity returns True for the same file"""
        result = verify_integrity(self.temp_file1.name, self.temp_file1.name)
        self.assertTrue(result)

    def test_verify_integrity_nonexistent_file(self):
        """Test that verify_integrity raises FileNotFoundError for non-existent file"""
        with self.assertRaises(FileNotFoundError):
            verify_integrity(self.temp_file1.name, "nonexistent_file.txt")

    def test_hash_empty_file(self):
        """Test hashing an empty file"""
        temp_empty = tempfile.NamedTemporaryFile(mode='w', delete=False)
        temp_empty.close()

        try:
            result = hash_file(temp_empty.name)
            # Empty file should still produce a valid SHA-256 hash
            self.assertEqual(len(result), 64)
            # Known SHA-256 hash of empty file
            self.assertEqual(result, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        finally:
            os.unlink(temp_empty.name)


if __name__ == '__main__':
    unittest.main()
