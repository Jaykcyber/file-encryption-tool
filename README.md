# file-encryption-tool
# File Encryption Tool - Project Documentation

## 🛠️ Developed by Team **EncryptEase**

**Total Members:** 4
- 🧑‍💻 **Jay Kumar**
- 👩‍💻 **Akaisha Sundhan** 
- 🧑‍💻 **Badal Pal**
- 👨‍💻 **Dhaval Thakker**

---

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Security Features](#security-features)
4. [Core Components](#core-components)
5. [How It Works](#how-it-works)
6. [User Interface](#user-interface)
7. [Technical Implementation](#technical-implementation)
8. [Error Handling](#error-handling)
9. [Configuration](#configuration)
10. [File Format](#file-format)
11. [Installation & Usage](#installation--usage)
12. [Security Considerations](#security-considerations)

---

## 🎯 Project Overview

The **File Encryption Tool** is an enterprise-grade, web-based application that provides secure file encryption and decryption capabilities. Built with Python and Streamlit, it offers a user-friendly interface while maintaining high security standards through industry-standard cryptographic algorithms.

### Key Features:
- **Web-based Interface**: Easy-to-use Streamlit web application
- **Enterprise-grade Security**: Uses Fernet encryption (AES-128 in CBC mode with HMAC-SHA256)
- **File Integrity Verification**: SHA-256 hash verification to ensure file hasn't been tampered with
- **Configurable Security Parameters**: Adjustable PBKDF2 iterations and other security settings
- **Memory Efficient**: Processes large files in chunks to optimize memory usage
- **Comprehensive Error Handling**: Custom exception hierarchy for different error scenarios

---

## 🏗️ Architecture

The project follows a modular architecture with clear separation of concerns:

```
File Encryption Tool
├── Encryption Logic Layer
│   ├── Core Classes
│   ├── Exception Handling
│   └── Security Functions
└── Web Interface Layer
    ├── Streamlit UI
    ├── User Interactions
    └── File Operations
```

### Core Modules:
1. **Encryption Engine** (`FileEncryptionTool`)
2. **Configuration Management** (`EncryptionConfig`)
3. **Metadata Handling** (`EncryptionMetadata`)
4. **Web Interface** (Streamlit components)
5. **Exception System** (Custom error hierarchy)

---

## 🔐 Security Features

### Cryptographic Implementation:
- **Algorithm**: Fernet (AES-128 in CBC mode with HMAC-SHA256)
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Salt Generation**: Cryptographically secure random salt (32 bytes)
- **Iterations**: Configurable PBKDF2 iterations (default: 100,000)
- **Integrity Check**: SHA-256 hash verification

### Security Measures:
- **Password Validation**: Ensures non-empty passwords
- **Salt Uniqueness**: Each encryption uses a unique salt
- **Secure Random Generation**: Uses `secrets` module for cryptographic randomness
- **Memory Management**: Secure cleanup of temporary files
- **File Size Limits**: Configurable maximum file size (default: 100MB)

---

## 🔧 Core Components

### 1. FileEncryptionTool Class
**Purpose**: Main encryption/decryption engine

**Key Methods**:
- `encrypt_file()`: Encrypts files with password-based encryption
- `decrypt_file()`: Decrypts previously encrypted files
- `verify_file_integrity()`: Validates encrypted file structure
- `_derive_key()`: Generates encryption key from password and salt
- `_calculate_file_hash()`: Computes SHA-256 hash for integrity verification

### 2. EncryptionConfig Class
**Purpose**: Configuration management for encryption parameters

**Parameters**:
```python
pbkdf2_iterations: int = 100_000    # Security iterations
salt_length: int = 32               # Salt size in bytes
chunk_size: int = 64 * 1024        # File processing chunk size
backup_original: bool = False       # Original file backup
verify_integrity: bool = True       # Enable integrity checks
max_file_size: int = 100 * 1024 * 1024  # Maximum file size
```

### 3. EncryptionMetadata Class
**Purpose**: Stores encryption metadata within encrypted files

**Metadata Fields**:
- `version`: Tool version for compatibility
- `algorithm`: Encryption algorithm used
- `timestamp`: Creation timestamp
- `file_hash`: Original file SHA-256 hash
- `iterations`: PBKDF2 iterations used
- `salt_length`: Salt length used

### 4. Exception Hierarchy
**Purpose**: Comprehensive error handling

**Exception Types**:
- `FileEncryptionError`: Base exception
- `InvalidPasswordError`: Wrong password errors
- `CorruptedFileError`: File integrity issues
- `FileNotFoundError`: Missing file errors
- `InsufficientPermissionsError`: Permission issues
- `UnsupportedFileTypeError`: File type restrictions

---

## ⚙️ How It Works

### Encryption Process:

1. **File Validation**
   - Check file exists and is accessible
   - Verify file size within limits
   - Validate file permissions

2. **Key Generation**
   ```
   User Password + Random Salt → PBKDF2-HMAC-SHA256 → Encryption Key
   ```

3. **Metadata Creation**
   - Generate encryption metadata
   - Calculate original file hash (if integrity check enabled)
   - Store configuration parameters

4. **File Structure Creation**
   ```
   [Metadata Length (4 bytes)] + [Metadata JSON] + [Salt] + [Encrypted Chunks]
   ```

5. **Chunk Encryption**
   - Read file in configurable chunks (default: 64KB)
   - Encrypt each chunk using Fernet
   - Write encrypted chunks with length prefixes

### Decryption Process:

1. **File Structure Parsing**
   - Read metadata length and extract metadata
   - Parse encryption parameters
   - Extract salt for key derivation

2. **Key Derivation**
   - Use stored salt and user password
   - Apply same PBKDF2 parameters as encryption

3. **Chunk Decryption**
   - Read encrypted chunks sequentially
   - Decrypt using derived key
   - Write decrypted data to output file

4. **Integrity Verification**
   - Calculate SHA-256 hash of decrypted file
   - Compare with stored hash in metadata
   - Report any integrity violations

---

## 🖥️ User Interface

### Web Interface Features:

#### Main Tabs:
1. **🔒 Encrypt File**
   - File upload component
   - Password input with confirmation
   - Progress indicators
   - Download encrypted file

2. **🔓 Decrypt File**
   - Encrypted file upload
   - Password input
   - Decryption progress
   - Download original file

3. **ℹ️ File Info**
   - Encrypted file analysis
   - Integrity verification
   - Metadata display
   - Security feature overview

#### Sidebar Configuration:
- **PBKDF2 Iterations Slider**: Security vs. performance trade-off
- **Integrity Verification Toggle**: Enable/disable hash checks
- **Real-time Configuration Updates**: Apply changes immediately

#### Team Credits Section:
- Expandable team information
- Member details and roles
- Project dedication message

---

## 💻 Technical Implementation

### Dependencies:
```python
# Core Python Libraries
import os, sys, logging, hashlib, secrets, tempfile
from pathlib import Path
from typing import Optional, Union, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json, base64

# Cryptography Libraries
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Web Interface
import streamlit as st
```

### Key Algorithms:

#### PBKDF2 Key Derivation:
```python
def _derive_key(self, password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for Fernet
        salt=salt,
        iterations=self.config.pbkdf2_iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key
```

#### File Hash Calculation:
```python
def _calculate_file_hash(self, file_path: Path) -> str:
    hash_sha256 = hashlib.sha256()
    with file_path.open('rb') as f:
        for chunk in iter(lambda: f.read(self.config.chunk_size), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()
```

### Memory Management:
- **Chunk-based Processing**: Files processed in 64KB chunks by default
- **Temporary File Handling**: Automatic cleanup of temporary files
- **Memory Efficiency**: Large files don't load entirely into memory

---

## 🚨 Error Handling

### Exception Categories:

1. **Security Errors**
   - Invalid passwords
   - Corrupted encryption data
   - Integrity check failures

2. **File System Errors**
   - File not found
   - Insufficient permissions
   - Unsupported file types

3. **Configuration Errors**
   - Invalid PBKDF2 iterations
   - Incorrect salt lengths
   - Invalid chunk sizes

### Error Recovery:
- **Partial File Cleanup**: Removes incomplete encrypted/decrypted files on error
- **Graceful Degradation**: Continues operation when possible
- **User-Friendly Messages**: Clear error descriptions for users

---

## ⚙️ Configuration

### Security Configuration:
```python
@dataclass
class EncryptionConfig:
    pbkdf2_iterations: int = 100_000     # OWASP minimum recommendation
    salt_length: int = 32                # 256-bit salt
    chunk_size: int = 64 * 1024         # 64KB chunks
    backup_original: bool = False        # Disabled for web interface
    verify_integrity: bool = True        # Enable hash verification
    log_operations: bool = False         # Disabled for web interface
    max_file_size: int = 100 * 1024 * 1024  # 100MB limit
```

### Validation Rules:
- Minimum PBKDF2 iterations: 10,000
- Minimum salt length: 16 bytes
- Minimum chunk size: 1,024 bytes

---

## 📄 File Format

### Encrypted File Structure:
```
+------------------+
| Metadata Length  |  (4 bytes, big-endian)
+------------------+
| Metadata JSON    |  (variable length)
+------------------+
| Salt             |  (32 bytes default)
+------------------+
| Chunk 1 Length   |  (4 bytes, big-endian)
+------------------+
| Encrypted Chunk 1|  (variable length)
+------------------+
| Chunk 2 Length   |  (4 bytes, big-endian)
+------------------+
| Encrypted Chunk 2|  (variable length)
+------------------+
| ...              |  (additional chunks)
+------------------+
```

### Metadata JSON Structure:
```json
{
    "version": "1.0",
    "algorithm": "Fernet",
    "timestamp": "2025-08-09T10:30:45.123456+00:00",
    "file_hash": "sha256_hash_of_original_file",
    "iterations": 100000,
    "salt_length": 32
}
```

---

## 🚀 Installation & Usage

### Prerequisites:
```bash
pip install cryptography streamlit
```

### Running the Application:
```bash
streamlit run complete_file_encryption.py
```

### Usage Flow:
1. **Start Application**: Launch Streamlit interface
2. **Configure Settings**: Adjust security parameters in sidebar
3. **Encrypt Files**: Upload file, set password, download encrypted version
4. **Decrypt Files**: Upload encrypted file, enter password, download original
5. **Verify Files**: Check encrypted file integrity and view metadata

---

## 🔒 Security Considerations

### Strengths:
- **Industry Standard Algorithms**: Uses vetted cryptographic libraries
- **Proper Key Derivation**: PBKDF2 with high iteration count
- **Unique Salts**: Each encryption uses a fresh random salt
- **Integrity Protection**: HMAC prevents tampering
- **Secure Random Generation**: Cryptographically secure randomness

### Best Practices Implemented:
- **No Password Storage**: Passwords never stored or logged
- **Secure Cleanup**: Temporary files securely deleted
- **Memory Protection**: Sensitive data cleared when possible
- **Error Information**: Prevents information leakage through errors

### User Recommendations:
- **Strong Passwords**: Use long, complex passwords
- **Secure Storage**: Store encrypted files and passwords separately
- **Regular Updates**: Keep dependencies updated
- **Backup Strategy**: Maintain secure backups of encrypted files

### Limitations:
- **Password Dependency**: Cannot recover files without password
- **Single Point of Failure**: Password compromise means data compromise
- **Performance Trade-off**: Higher security means slower processing

---

## 📊 Performance Characteristics

### Encryption Speed:
- **Small Files (<1MB)**: Near-instantaneous
- **Medium Files (1-10MB)**: 1-5 seconds
- **Large Files (10-100MB)**: 10-60 seconds

### Memory Usage:
- **Base Memory**: ~50MB (Streamlit + libraries)
- **Processing Memory**: ~1MB additional (chunk-based processing)
- **Peak Memory**: Independent of file size

### Scalability:
- **File Size**: Limited by configured maximum (default: 100MB)
- **Concurrent Users**: Limited by server resources
- **Storage**: No persistent storage requirements

---

## 🎯 Future Enhancements

### Potential Improvements:
1. **Multiple File Support**: Batch encryption/decryption
2. **Cloud Storage Integration**: Direct cloud platform support
3. **Advanced Key Management**: Key derivation from multiple sources
4. **Mobile Interface**: Responsive design for mobile devices
5. **Audit Logging**: Optional operation logging for enterprise use
6. **Digital Signatures**: File authenticity verification
7. **Compression**: Built-in file compression before encryption

### Security Enhancements:
1. **Two-Factor Authentication**: Additional authentication layer
2. **Key Escrow**: Secure key recovery mechanisms
3. **Hardware Security Modules**: HSM integration for key storage
4. **Advanced Algorithms**: Support for post-quantum cryptography

---

## 📝 Conclusion

The File Encryption Tool demonstrates a comprehensive approach to secure file encryption, combining robust cryptographic implementation with user-friendly design. The project successfully balances security, performance, and usability while maintaining clean, maintainable code architecture.

The tool provides enterprise-grade security features through industry-standard algorithms and best practices, making it suitable for both personal and professional use cases where file security is paramount.

---

**Project Completion Date**: August 2025  
**Documentation Version**: 1.0  
**Team EncryptEase** - Dedicated to secure and accessible encryption solutions.
