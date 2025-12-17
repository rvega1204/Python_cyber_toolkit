# Cybersecurity Toolkit

A comprehensive command-line cybersecurity toolkit that provides various cryptographic and security utilities for file hashing, encryption, password management, and encoding.

## Features

- **File Hashing**: Compute SHA-256 hashes of files
- **File Integrity Verification**: Compare files to verify they are identical
- **AES-256-GCM Encryption**: Symmetric encryption with authenticated encryption
- **RSA-2048 Encryption**: Asymmetric encryption with OAEP padding
- **Password Strength Evaluation**: Analyze password security using zxcvbn
- **Secure Password Hashing**: Hash passwords using bcrypt with salt
- **Strong Password Generator**: Generate cryptographically secure random passwords
- **Base64 Encoding/Decoding**: Encode and decode text in Base64 format

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
  - [Hash Module](#hash-module)
  - [Encryption Module](#encryption-module)
  - [Password Module](#password-module)
  - [Encoding Module](#encoding-module)
- [Examples](#examples)
- [Testing](#testing)
- [Requirements](#requirements)
- [Security Considerations](#security-considerations)
- [License](#license)

## Installation

1. Clone this repository or download the source code:
```bash
git clone https://github.com/rvega1204/cyber_toolkit.git
cd cyber_toolkit
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On Linux/Mac
source venv/bin/activate
```

3. Install the required dependencies:
```bash
pip install bcrypt cryptography zxcvbn
```

## Usage

Run the main application to launch the interactive menu:

```bash
python main.py
```

### Menu Options

The application provides the following options:

1. **Hash a file** - Compute the SHA-256 hash of any file
2. **Verify file integrity** - Compare two files to check if they are identical
3. **AES Encrypt/Decrypt** - Demonstrate symmetric encryption using AES-256-GCM
4. **RSA Encrypt/Decrypt** - Demonstrate asymmetric encryption using RSA-2048
5. **Password Manager** - Evaluate password strength and generate secure hashes
6. **Generate Strong Password** - Create cryptographically secure random passwords
7. **Base64 Encode/Decode** - Encode and decode text in Base64 format
0. **Exit** - Quit the application

## Modules

### Hash Module

Located in `modules/hash.py`, this module provides file hashing functionality.

#### Functions:

- **`hash_file(file_path)`**: Computes the SHA-256 hash of a file
  - Parameters: `file_path` (str) - Path to the file to hash
  - Returns: Hexadecimal string representation of the hash
  - Uses chunk-based reading for memory efficiency with large files

- **`verify_integrity(file1, file2)`**: Verifies if two files are identical
  - Parameters: `file1` (str), `file2` (str) - Paths to files to compare
  - Returns: `True` if files are identical, `False` otherwise

### Encryption Module

Located in `modules/encryption.py`, this module provides encryption and decryption capabilities.

#### Functions:

- **`aes_encrypt_decrypt(message)`**: Encrypts and decrypts using AES-256-GCM
  - Parameters: `message` (str) - The plaintext message
  - Returns: Tuple of (key, ciphertext, decrypted_message) in hexadecimal format
  - Provides authenticated encryption with confidentiality and integrity

- **`rsa_encrypt_decrypt(message)`**: Encrypts and decrypts using RSA-2048
  - Parameters: `message` (str) - The plaintext message
  - Returns: Tuple of (ciphertext, decrypted_message)
  - Uses OAEP padding with SHA-256 for security

### Password Module

Located in `modules/password.py`, this module handles password security operations.

#### Functions:

- **`evaluate_password_strength(password)`**: Analyzes password strength
  - Parameters: `password` (str) - The password to evaluate
  - Returns: None (prints results to console)
  - Provides a score from 0-4 with actionable suggestions
  - Score interpretation:
    - 0: Too guessable (risky)
    - 1: Very guessable (protection from throttled online attacks)
    - 2: Somewhat guessable (protection from unthrottled online attacks)
    - 3: Safely unguessable (moderate offline protection)
    - 4: Very unguessable (strong offline protection)

- **`hash_password(password)`**: Creates a secure bcrypt hash
  - Parameters: `password` (str) - The plaintext password
  - Returns: bytes - The bcrypt hash including salt and cost factor
  - Automatically generates salt for protection against rainbow tables

- **`verify_password(password, hashed)`**: Verifies a password against a hash
  - Parameters: `password` (str), `hashed` (bytes) - Password and stored hash
  - Returns: `True` if password matches, `False` otherwise
  - Uses constant-time comparison to prevent timing attacks

- **`create_strong_password(length=16)`**: Generates a strong random password
  - Parameters: `length` (int, optional) - Password length (minimum 16)
  - Returns: str - A cryptographically secure random password
  - Guarantees at least one uppercase, lowercase, digit, and special character
  - Uses the `secrets` module for cryptographic randomness

### Encoding Module

Located in `modules/encoding.py`, this module provides encoding and decoding utilities.

#### Functions:

- **`encode_base64(text)`**: Encodes text to Base64 format
  - Parameters: `text` (str) - The plaintext to encode
  - Returns: str - The Base64 encoded string
  - Handles UTF-8 encoding automatically

- **`decode_base64(encoded_text)`**: Decodes Base64 to plaintext
  - Parameters: `encoded_text` (str) - The Base64 string to decode
  - Returns: str - The decoded plaintext, or None if invalid
  - Includes error handling for invalid Base64 input

## Examples

### Example 1: Hashing a File

```python
from modules.hash import hash_file

file_hash = hash_file('document.txt')
print(f"SHA-256: {file_hash}")
```

### Example 2: Verifying File Integrity

```python
from modules.hash import verify_integrity

is_identical = verify_integrity('original.txt', 'copy.txt')
if is_identical:
    print("Files are identical")
else:
    print("Files differ")
```

### Example 3: AES Encryption

```python
from modules.encryption import aes_encrypt_decrypt

key, ciphertext, decrypted = aes_encrypt_decrypt("Secret message")
print(f"Key: {key}")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted: {decrypted}")
```

### Example 4: RSA Encryption

```python
from modules.encryption import rsa_encrypt_decrypt

ciphertext, decrypted = rsa_encrypt_decrypt("Secret message")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted: {decrypted}")
```

### Example 5: Password Security

```python
from modules.password import evaluate_password_strength, hash_password, verify_password

# Evaluate strength
evaluate_password_strength("MyPassword123!")

# Hash password
hashed = hash_password("MyPassword123!")
print(f"Hashed: {hashed.decode()}")

# Verify password
is_valid = verify_password("MyPassword123!", hashed)
print(f"Valid: {is_valid}")
```

### Example 6: Generate Strong Password

```python
from modules.password import create_strong_password, evaluate_password_strength

# Generate default length password (16 characters)
password = create_strong_password()
print(f"Generated: {password}")

# Generate custom length password
long_password = create_strong_password(24)
print(f"Generated (24 chars): {long_password}")

# Evaluate the generated password
evaluate_password_strength(password)
```

### Example 7: Base64 Encoding

```python
from modules.encoding import encode_base64, decode_base64

# Encode text
text = "Hello World!"
encoded = encode_base64(text)
print(f"Encoded: {encoded}")

# Decode text
decoded = decode_base64(encoded)
print(f"Decoded: {decoded}")
```

## Testing

The project includes comprehensive unit tests for all modules.

### Running Tests

To run all tests:

```bash
# From the project root directory
python -m unittest discover tests

# Or run the test suite directly
python tests/run_all_tests.py
```

To run individual test files:

```bash
# Test password module
python -m unittest tests.test_password

# Test encoding module
python -m unittest tests.test_encoding

# Test hash module
python -m unittest tests.test_hash

# Test encryption module
python -m unittest tests.test_encryption
```

### Test Coverage

The test suite includes:
- **test_password.py**: 8 tests for password hashing, verification, and generation
- **test_encoding.py**: 10 tests for Base64 encoding and decoding
- **test_hash.py**: 11 tests for file hashing and integrity verification
- **test_encryption.py**: 19 tests for AES and RSA encryption/decryption

All tests verify:
- Correct functionality with valid inputs
- Proper error handling with invalid inputs
- Edge cases (empty strings, special characters, Unicode)
- Security properties (uniqueness, format validation)

## Requirements

- Python 3.7+
- bcrypt
- cryptography
- zxcvbn

Install all requirements with:
```bash
pip install bcrypt cryptography zxcvbn
```

## Security Considerations

### For Production Use

This toolkit is designed for educational purposes and demonstrations. If you plan to use these components in production:

1. **Key Management**: Never hardcode or expose encryption keys. Use secure key management systems.

2. **Password Storage**: The bcrypt implementation is production-ready, but ensure you:
   - Never store plaintext passwords
   - Use appropriate cost factors for bcrypt (default is secure)
   - Implement rate limiting on authentication endpoints

3. **Encryption Best Practices**:
   - For RSA: Messages have size limitations. Use hybrid encryption for larger data.
   - For AES: Securely store and manage keys separately from ciphertext.
   - Never reuse nonces with the same key in AES-GCM.

4. **File Hashing**: SHA-256 is cryptographically secure for integrity verification but should not be used alone for password hashing (use bcrypt instead).

5. **Input Validation**: Always validate and sanitize user inputs, especially file paths.

6. **Error Handling**: Implement proper error handling to avoid information leakage through error messages.

## Project Structure

```
cyber_toolkit/
├── main.py                     # Main application entry point
├── modules/
│   ├── hash.py                 # File hashing and integrity verification
│   ├── encryption.py           # AES and RSA encryption operations
│   ├── password.py             # Password security and management
│   └── encoding.py             # Base64 encoding and decoding
├── tests/
│   ├── __init__.py             # Tests package initializer
│   ├── test_hash.py            # Unit tests for hash module
│   ├── test_encryption.py      # Unit tests for encryption module
│   ├── test_password.py        # Unit tests for password module
│   ├── test_encoding.py        # Unit tests for encoding module
│   └── run_all_tests.py        # Test runner for all modules
├── README.md                   # This file
├── .gitignore                  # Git ignore file
└── venv/                       # Virtual environment (not committed to git)
```

## Contributing

Contributions are welcome! Please ensure any pull requests:
- Follow Python PEP 8 style guidelines
- Include comprehensive docstrings
- Add appropriate error handling
- Include security considerations

## Author

Ricardo Vega

## Version

1.1

## License

This project is provided as-is for educational purposes.
