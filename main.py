"""
Cybersecurity Toolkit - Main Application

This is the main entry point for the Cybersecurity Toolkit, an interactive
command-line application that provides various cryptographic and security
utilities.

Features:
    - File hashing with SHA-256
    - File integrity verification
    - AES-256-GCM symmetric encryption/decryption
    - RSA-2048 asymmetric encryption/decryption
    - Password strength evaluation
    - Secure password hashing with bcrypt

Usage:
    Run this script directly to launch the interactive menu:
        python main.py

Modules:
    - modules.hash: File hashing and integrity verification
    - modules.encryption: AES and RSA encryption operations
    - modules.password: Password security and management

Author: Ricardo Vega
Version: 1.0
"""

from modules.hash import hash_file, verify_integrity
from modules.password import evaluate_password_strength, hash_password, verify_password
from modules.encryption import aes_encrypt_decrypt, rsa_encrypt_decrypt


def menu():
    print("Cybersecurity Toolkit")
    print("Select an option:")
    print("1. Hash a file")
    print("2. Verify file integrity")
    print("3. AES Encrypt/Decrypt")
    print("4. RSA Encrypt/Decrypt")
    print("5. Password Manager")
    print("0. Exit")

    while True:
        choice = input("Enter choice (0-5): ")
        if choice == '1':
            file_path = input("Enter file path to hash: ")
            print(f"SHA-256: {hash_file(file_path)}")
        elif choice == '2':
            file1 = input("Enter first file path: ")
            file2 = input("Enter second file path: ")
            result = verify_integrity(file1, file2)
            print(f"Files are identical: {result}")
        elif choice == '3':
            message = input("Enter message to AES encrypt/decrypt: ")
            key, ciphertext, decrypted_message = aes_encrypt_decrypt(message)
            print(f"AES Key: {key}")
            print(f"AES Ciphertext: {ciphertext}")
            print(f"AES Decrypted Message: {decrypted_message}")
        elif choice == '4':
            message = input("Enter message to RSA encrypt/decrypt: ")
            ciphertext, decrypted_message = rsa_encrypt_decrypt(message)
            print(f"RSA message, encrypted with a publick key: {ciphertext}")
            print(f"RSA message, decrypted with a private key: {decrypted_message}")
        elif choice == '5':
            password = input("Enter a password to evaluate: ")
            evaluate_password_strength(password)
            hashed = hash_password(password)
            print(f"Hashed Password: {hashed.decode()}")
            verification = verify_password(password, hashed)
            print(f"Password verification result: {verification}")
        elif choice == '0':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()