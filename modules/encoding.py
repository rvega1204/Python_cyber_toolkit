"""
Encoding Utilities Module

This module provides encoding and decoding utilities for common formats
used in cybersecurity and data transmission.

Features:
    - Base64 encoding and decoding
    - Support for text and binary data

Functions:
    encode_base64(text): Encode text to Base64
    decode_base64(encoded_text): Decode Base64 to text
"""

import base64


def encode_base64(text):
    """
    Encode a text string to Base64 format.

    Base64 encoding is commonly used to encode binary data as ASCII text,
    making it safe for transmission over text-based protocols like email
    or JSON APIs.

    Args:
        text (str): The plaintext string to encode

    Returns:
        str: The Base64 encoded string

    Example:
        >>> encoded = encode_base64("Hello World!")
        >>> print(encoded)
        SGVsbG8gV29ybGQh

    Note:
        The function handles UTF-8 encoding automatically, so it can
        handle international characters.
    """
    try:
        text_bytes = text.encode('utf-8')
        base64_bytes = base64.b64encode(text_bytes)
        base64_string = base64_bytes.decode('utf-8')
        return base64_string
    except Exception as e:
        print(f"Error encoding to Base64: {e}")
        return None


def decode_base64(encoded_text):
    """
    Decode a Base64 encoded string back to plaintext.

    Decodes Base64 encoded data back to its original text format.
    Handles UTF-8 decoding automatically.

    Args:
        encoded_text (str): The Base64 encoded string to decode

    Returns:
        str: The decoded plaintext string, or None if decoding fails

    Example:
        >>> decoded = decode_base64("SGVsbG8gV29ybGQh")
        >>> print(decoded)
        Hello World!

    Note:
        Invalid Base64 input will return None and print an error message.
        Common issues include missing padding or invalid characters.
    """
    try:
        base64_bytes = encoded_text.encode('utf-8')
        text_bytes = base64.b64decode(base64_bytes)
        text = text_bytes.decode('utf-8')
        return text
    except Exception as e:
        print(f"Error decoding from Base64: {e}")
        return None
