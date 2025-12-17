"""
Unit tests for the encoding module
"""

import unittest
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.encoding import encode_base64, decode_base64


class TestEncodingModule(unittest.TestCase):
    """Test cases for Base64 encoding/decoding functions"""

    def test_encode_base64_simple_text(self):
        """Test Base64 encoding with simple text"""
        text = "Hello World!"
        expected = "SGVsbG8gV29ybGQh"

        result = encode_base64(text)
        self.assertEqual(result, expected)

    def test_encode_base64_empty_string(self):
        """Test Base64 encoding with empty string"""
        text = ""
        expected = ""

        result = encode_base64(text)
        self.assertEqual(result, expected)

    def test_encode_base64_special_characters(self):
        """Test Base64 encoding with special characters"""
        text = "Test@#$%^&*()"

        result = encode_base64(text)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)

    def test_encode_base64_unicode(self):
        """Test Base64 encoding with Unicode characters"""
        text = "Hola 世界 🌍"

        result = encode_base64(text)
        self.assertIsNotNone(result)
        # Verify it can be decoded back
        decoded = decode_base64(result)
        self.assertEqual(decoded, text)

    def test_decode_base64_simple_text(self):
        """Test Base64 decoding with simple text"""
        encoded = "SGVsbG8gV29ybGQh"
        expected = "Hello World!"

        result = decode_base64(encoded)
        self.assertEqual(result, expected)

    def test_decode_base64_empty_string(self):
        """Test Base64 decoding with empty string"""
        encoded = ""
        expected = ""

        result = decode_base64(encoded)
        self.assertEqual(result, expected)

    def test_decode_base64_invalid_input(self):
        """Test Base64 decoding with invalid input"""
        invalid_encoded = "This is not valid Base64!!!"

        result = decode_base64(invalid_encoded)
        self.assertIsNone(result)

    def test_encode_decode_roundtrip(self):
        """Test that encoding and then decoding returns original text"""
        original_texts = [
            "Simple text",
            "Text with numbers 12345",
            "Special chars: !@#$%^&*()",
            "Multi\nLine\nText",
            "Tab\tSeparated\tValues"
        ]

        for original in original_texts:
            with self.subTest(text=original):
                encoded = encode_base64(original)
                decoded = decode_base64(encoded)
                self.assertEqual(decoded, original)

    def test_encode_base64_long_text(self):
        """Test Base64 encoding with long text"""
        text = "A" * 1000

        result = encode_base64(text)
        self.assertIsNotNone(result)
        # Verify length is appropriate (Base64 is roughly 4/3 of original)
        self.assertGreater(len(result), len(text))

    def test_decode_base64_with_padding(self):
        """Test Base64 decoding with proper padding"""
        # Base64 with padding (=)
        encoded = "VGVzdA=="
        expected = "Test"

        result = decode_base64(encoded)
        self.assertEqual(result, expected)


if __name__ == '__main__':
    unittest.main()
