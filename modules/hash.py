"""
File Hashing and Integrity Verification Module

This module provides functionality for computing SHA-256 hashes of files
and verifying file integrity by comparing hashes.

Functions:
    hash_file(file_path): Computes SHA-256 hash of a file
    verify_integrity(file1, file2): Verifies if two files are identical
"""

import hashlib


def hash_file(file_path):
    """
    Compute the SHA-256 hash of a file.

    This function reads a file in chunks to efficiently handle large files
    without loading the entire file into memory.

    Args:
        file_path (str): Path to the file to be hashed

    Returns:
        str: Hexadecimal representation of the SHA-256 hash

    Raises:
        FileNotFoundError: If the specified file does not exist
        PermissionError: If the file cannot be read due to permissions

    Example:
        >>> hash_value = hash_file('document.txt')
        >>> print(f"SHA-256: {hash_value}")
    """
    try:
        h = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(1024)
                if chunk == b'':
                    break
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        raise


def verify_integrity(file1, file2):
    """
    Verify the integrity of two files by comparing their SHA-256 hashes.

    This function computes the SHA-256 hash of both files and compares them
    to determine if the files are identical.

    Args:
        file1 (str): Path to the first file
        file2 (str): Path to the second file

    Returns:
        bool: True if files are identical, False otherwise

    Raises:
        FileNotFoundError: If either file does not exist
        PermissionError: If either file cannot be read

    Example:
        >>> is_same = verify_integrity('original.txt', 'copy.txt')
        >>> if is_same:
        >>>     print("Files are identical")
    """
    try:
        print("Verifying integrity...")
        return hash_file(file1) == hash_file(file2)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        raise