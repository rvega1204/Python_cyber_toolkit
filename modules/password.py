"""
Password Security Module

This module provides comprehensive password security functionality including
strength evaluation, secure hashing, and password verification.

Features:
    - Password strength analysis using zxcvbn
    - Secure password hashing with bcrypt
    - Password verification against stored hashes
    - Strong random password generation

Functions:
    evaluate_password_strength(password): Analyzes password strength
    hash_password(password): Creates a secure bcrypt hash
    verify_password(password, hashed): Verifies password against hash
    create_strong_password(length): Generates a strong random password
"""

import bcrypt
from zxcvbn import zxcvbn
import hashlib
import secrets
import string


def evaluate_password_strength(password):
    """
    Evaluate the strength of a password and provide feedback.

    Uses the zxcvbn library to analyze password strength based on pattern
    matching, dictionary attacks, and common password patterns. Provides
    a score from 0-4 and actionable suggestions for improvement.

    Args:
        password (str): The password to evaluate

    Returns:
        None: Prints the evaluation results directly to console

    Score Interpretation:
        0 = Too guessable (risky password)
        1 = Very guessable (protection from throttled online attacks)
        2 = Somewhat guessable (protection from unthrottled online attacks)
        3 = Safely unguessable (moderate protection from offline attacks)
        4 = Very unguessable (strong protection from offline attacks)

    Example:
        >>> evaluate_password_strength("password123")
        Password Strength Score: 0/4
        Warning: This is a very common password
        Suggestions:
        - Add another word or two. Uncommon words are better.

    Note:
        Results are printed to console including warnings and suggestions
        for improving password strength.
    """
    try:
        result = zxcvbn(password)
        score = result['score']
        feedback = result['feedback']
        print(f"Password Strength Score: {score}/4")
        if feedback['warning']:
            print(f"Warning: {feedback['warning']}")
        if feedback['suggestions']:
            print("Suggestions:")
            for suggestion in feedback['suggestions']:
                print(f"- {suggestion}")
    except Exception as e:
        print(f"Error evaluating password strength: {e}")


def hash_password(password):
    """
    Hash a password securely using bcrypt.

    Generates a secure hash of the password using bcrypt with an automatically
    generated salt. Bcrypt is specifically designed for password hashing and
    includes protection against rainbow table attacks.

    Args:
        password (str): The plaintext password to hash

    Returns:
        bytes: The bcrypt hash including the salt

    Example:
        >>> hashed = hash_password("MySecurePassword123!")
        >>> print(hashed.decode())
        $2b$12$...

    Note:
        The returned hash includes the salt and cost factor, so it can be
        used directly for verification. Store this hash securely in your database.
    """
    try:
        salt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password.encode(), salt)
        return pwd_hash
    except Exception as e:
        print(f"Error hashing password: {e}")


def verify_password(password, hashed):
    """
    Verify a password against a stored bcrypt hash.

    Checks if the provided password matches the stored hash using bcrypt's
    secure comparison function, which is resistant to timing attacks.

    Args:
        password (str): The plaintext password to verify
        hashed (bytes): The stored bcrypt hash to compare against

    Returns:
        bool: True if the password matches, False otherwise

    Example:
        >>> hashed = hash_password("MyPassword")
        >>> is_valid = verify_password("MyPassword", hashed)
        >>> print(is_valid)
        True
        >>> is_invalid = verify_password("WrongPassword", hashed)
        >>> print(is_invalid)
        False

    Note:
        This function uses constant-time comparison to prevent timing attacks.
    """
    try:
        return bcrypt.checkpw(password.encode(), hashed)
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False



def create_strong_password(length=16):
    """
    Generate a strong random password with numbers and special characters.

    Creates a cryptographically secure random password using the secrets module,
    which is suitable for security-sensitive applications. The password will
    include uppercase letters, lowercase letters, digits, and special characters.

    Args:
        length (int, optional): The length of the password. Defaults to 16.
                                Minimum length is 16 for security.

    Returns:
        str: A strong random password

    Example:
        >>> password = create_strong_password()
        >>> print(f"Generated password: {password}")
        Generated password: K9#mP2$xQ7!wE3&h
        >>> password = create_strong_password(20)
        >>> print(f"Generated password: {password}")
        Generated password: A8#bC2$dE9!fG3&hI7%j

    Note:
        The password will always contain at least one character from each
        category (uppercase, lowercase, digit, special character) to ensure
        strength and meet common password requirements.
    """
    if length < 16:
        raise ValueError("Password length must be at least 16 characters for security")

    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    # Combine all characters
    all_chars = uppercase + lowercase + digits + special_chars

    # Ensure at least one character from each category
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special_chars)
    ]

    # Fill the rest of the password length with random characters
    password += [secrets.choice(all_chars) for _ in range(length - 4)]

    # Shuffle the password to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)