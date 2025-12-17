"""
Unit tests for the encryption module
"""

import unittest
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.encryption import aes_encrypt_decrypt, rsa_encrypt_decrypt


class TestEncryptionModule(unittest.TestCase):
    """Test cases for AES and RSA encryption/decryption functions"""

    def test_aes_encrypt_decrypt_simple_message(self):
        """Test AES encryption and decryption with simple message"""
        message = "Hello World!"

        key, ciphertext, decrypted = aes_encrypt_decrypt(message)

        self.assertIsNotNone(key)
        self.assertIsNotNone(ciphertext)
        self.assertEqual(decrypted, message)

    def test_aes_key_format(self):
        """Test that AES key is in correct format"""
        message = "Test message"

        key, ciphertext, decrypted = aes_encrypt_decrypt(message)

        # AES-256 key should be 64 hex characters (32 bytes)
        self.assertEqual(len(key), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in key))

    def test_aes_ciphertext_differs_from_plaintext(self):
        """Test that AES ciphertext is different from plaintext"""
        message = "Secret message"

        key, ciphertext, decrypted = aes_encrypt_decrypt(message)

        # Ciphertext should not contain the plaintext
        self.assertNotIn(message, ciphertext)

    def test_aes_empty_message(self):
        """Test AES encryption with empty message"""
        message = ""

        key, ciphertext, decrypted = aes_encrypt_decrypt(message)

        self.assertEqual(decrypted, message)

    def test_aes_special_characters(self):
        """Test AES encryption with special characters"""
        message = "Special!@#$%^&*()_+-={}[]|:;<>?,."

        key, ciphertext, decrypted = aes_encrypt_decrypt(message)

        self.assertEqual(decrypted, message)

    def test_aes_unicode_characters(self):
        """Test AES encryption with Unicode characters"""
        message = "Hello 世界 🌍"

        key, ciphertext, decrypted = aes_encrypt_decrypt(message)

        self.assertEqual(decrypted, message)

    def test_aes_unique_keys(self):
        """Test that AES generates unique keys for each encryption"""
        message = "Same message"

        key1, _, _ = aes_encrypt_decrypt(message)
        key2, _, _ = aes_encrypt_decrypt(message)

        self.assertNotEqual(key1, key2)

    def test_aes_unique_ciphertext(self):
        """Test that AES generates unique ciphertext for same message"""
        message = "Same message"

        _, ciphertext1, _ = aes_encrypt_decrypt(message)
        _, ciphertext2, _ = aes_encrypt_decrypt(message)

        # Different nonces should produce different ciphertexts
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_rsa_encrypt_decrypt_simple_message(self):
        """Test RSA encryption and decryption with simple message"""
        message = "Hello RSA!"

        ciphertext, decrypted = rsa_encrypt_decrypt(message)

        self.assertIsNotNone(ciphertext)
        self.assertEqual(decrypted, message)

    def test_rsa_ciphertext_format(self):
        """Test that RSA ciphertext is in hexadecimal format"""
        message = "Test message"

        ciphertext, decrypted = rsa_encrypt_decrypt(message)

        # Should be hexadecimal
        self.assertTrue(all(c in '0123456789abcdef' for c in ciphertext))

    def test_rsa_ciphertext_differs_from_plaintext(self):
        """Test that RSA ciphertext is different from plaintext"""
        message = "Secret message"

        ciphertext, decrypted = rsa_encrypt_decrypt(message)

        # Ciphertext should not contain the plaintext
        self.assertNotIn(message, ciphertext)

    def test_rsa_empty_message(self):
        """Test RSA encryption with empty message"""
        message = ""

        ciphertext, decrypted = rsa_encrypt_decrypt(message)

        self.assertEqual(decrypted, message)

    def test_rsa_special_characters(self):
        """Test RSA encryption with special characters"""
        message = "Special!@#$%^&*()"

        ciphertext, decrypted = rsa_encrypt_decrypt(message)

        self.assertEqual(decrypted, message)

    def test_rsa_unicode_characters(self):
        """Test RSA encryption with Unicode characters"""
        message = "Hello 世界"

        ciphertext, decrypted = rsa_encrypt_decrypt(message)

        self.assertEqual(decrypted, message)

    def test_rsa_unique_ciphertext(self):
        """Test that RSA generates unique ciphertext for same message"""
        message = "Same message"

        ciphertext1, _ = rsa_encrypt_decrypt(message)
        ciphertext2, _ = rsa_encrypt_decrypt(message)

        # Different key pairs should produce different ciphertexts
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_aes_long_message(self):
        """Test AES encryption with long message"""
        message = "A" * 1000

        key, ciphertext, decrypted = aes_encrypt_decrypt(message)

        self.assertEqual(decrypted, message)

    def test_rsa_medium_message(self):
        """Test RSA encryption with medium-length message"""
        # RSA has message size limitations
        message = "This is a medium length message for RSA encryption testing."

        ciphertext, decrypted = rsa_encrypt_decrypt(message)

        self.assertEqual(decrypted, message)


if __name__ == '__main__':
    unittest.main()
