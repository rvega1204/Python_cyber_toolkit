"""
Unit tests for the password module
"""

import unittest
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.password import (
    evaluate_password_strength,
    hash_password,
    verify_password,
    create_strong_password
)


class TestPasswordModule(unittest.TestCase):
    """Test cases for password security functions"""

    def test_hash_password(self):
        """Test password hashing"""
        password = "TestPassword123!"
        hashed = hash_password(password)

        self.assertIsNotNone(hashed)
        self.assertIsInstance(hashed, bytes)
        self.assertTrue(hashed.startswith(b'$2b$'))  # bcrypt format

    def test_verify_password_correct(self):
        """Test password verification with correct password"""
        password = "CorrectPassword456!"
        hashed = hash_password(password)

        result = verify_password(password, hashed)
        self.assertTrue(result)

    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password"""
        password = "CorrectPassword789!"
        wrong_password = "WrongPassword000!"
        hashed = hash_password(password)

        result = verify_password(wrong_password, hashed)
        self.assertFalse(result)

    def test_create_strong_password_default_length(self):
        """Test strong password generation with default length"""
        password = create_strong_password()

        self.assertIsNotNone(password)
        self.assertEqual(len(password), 16)
        self.assertIsInstance(password, str)

    def test_create_strong_password_custom_length(self):
        """Test strong password generation with custom length"""
        length = 24
        password = create_strong_password(length)

        self.assertEqual(len(password), length)

    def test_create_strong_password_contains_required_chars(self):
        """Test that generated password contains all required character types"""
        password = create_strong_password(20)

        has_uppercase = any(c.isupper() for c in password)
        has_lowercase = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        self.assertTrue(has_uppercase, "Password should contain uppercase letters")
        self.assertTrue(has_lowercase, "Password should contain lowercase letters")
        self.assertTrue(has_digit, "Password should contain digits")
        self.assertTrue(has_special, "Password should contain special characters")

    def test_create_strong_password_minimum_length_error(self):
        """Test that creating password with length < 16 raises ValueError"""
        with self.assertRaises(ValueError):
            create_strong_password(10)

    def test_create_strong_password_uniqueness(self):
        """Test that generated passwords are unique"""
        password1 = create_strong_password()
        password2 = create_strong_password()

        self.assertNotEqual(password1, password2)


if __name__ == '__main__':
    unittest.main()
