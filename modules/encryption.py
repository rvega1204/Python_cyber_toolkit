"""
Encryption and Decryption Module

This module provides symmetric and asymmetric encryption/decryption functionality
using industry-standard cryptographic algorithms.

Algorithms:
    - AES-256-GCM: Symmetric encryption with authenticated encryption
    - RSA-2048: Asymmetric encryption with OAEP padding

Functions:
    aes_encrypt_decrypt(message): Encrypts and decrypts using AES-256-GCM
    rsa_encrypt_decrypt(message): Encrypts and decrypts using RSA-2048
"""

import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def aes_encrypt_decrypt(message):
    """
    Encrypt and decrypt a message using AES-256-GCM.

    This function demonstrates symmetric encryption by generating a random key,
    encrypting the message, and immediately decrypting it. AES-GCM provides both
    confidentiality and authenticity.

    Args:
        message (str): The plaintext message to encrypt

    Returns:
        tuple: A tuple containing:
            - key (str): Hexadecimal representation of the AES-256 key
            - ciphertext (str): Hexadecimal representation of nonce + encrypted data
            - decrypted_message (str): The decrypted plaintext message

    Example:
        >>> key, ciphertext, plaintext = aes_encrypt_decrypt("Secret message")
        >>> print(f"Key: {key}")
        >>> print(f"Ciphertext: {ciphertext}")
        >>> print(f"Decrypted: {plaintext}")

    Note:
        The nonce is prepended to the ciphertext for demonstration purposes.
        In production, the key should be securely stored and managed separately.
    """
    try:
        key = secrets.token_bytes(32)  # AES-256 key
        nonce = secrets.token_bytes(12)  # Recommended nonce size for AESGCM
        aesgcm = AESGCM(key)

        ciphertext = nonce + aesgcm.encrypt(nonce, message.encode(), None)
        decrypted_message = aesgcm.decrypt(nonce, ciphertext[12:], None)
        return key.hex(), ciphertext.hex(), decrypted_message.decode()
    except Exception as e:
        return None, None, f"Encryption/Decryption error: {str(e)}"


def rsa_encrypt_decrypt(message):
    """
    Encrypt and decrypt a message using RSA-2048.

    This function demonstrates asymmetric encryption by generating an RSA key pair,
    encrypting the message with the public key, and decrypting it with the private key.
    Uses OAEP padding with SHA-256 for security.

    Args:
        message (str): The plaintext message to encrypt

    Returns:
        tuple: A tuple containing:
            - ciphertext (str): Hexadecimal representation of encrypted data
            - decrypted_message (str): The decrypted plaintext message

    Example:
        >>> ciphertext, plaintext = rsa_encrypt_decrypt("Secret message")
        >>> print(f"Ciphertext: {ciphertext}")
        >>> print(f"Decrypted: {plaintext}")

    Note:
        RSA encryption has message size limitations. For messages longer than
        the key size minus padding overhead, use hybrid encryption instead.
        In production, private keys should be securely stored and never exposed.
    """
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        decrypted_message = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        return ciphertext.hex(), decrypted_message.decode()
    except Exception as e:
        return None, f"Encryption/Decryption error: {str(e)}"