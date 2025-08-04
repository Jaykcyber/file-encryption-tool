"""
Complete File Encryption Tool with Web Interface

A unified file containing both the encryption logic and Streamlit web interface.
"""

import os
import sys
import logging
import hashlib
import secrets
import tempfile
from pathlib import Path
from typing import Optional, Union, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

import streamlit as st


# ===== ENCRYPTION LOGIC =====

# Custom Exception Hierarchy
class FileEncryptionError(Exception):
    """Base exception for file encryption operations."""
    pass


class InvalidPasswordError(FileEncryptionError):
    """Raised when an invalid password is provided."""
    pass


class CorruptedFileError(FileEncryptionError):
    """Raised when a file appears to be corrupted or tampered with."""
    pass


class FileNotFoundError(FileEncryptionError):
    """Raised when a specified file cannot be found."""
    pass


class InsufficientPermissionsError(FileEncryptionError):
    """Raised when insufficient file system permissions are encountered."""
    pass


class UnsupportedFileTypeError(FileEncryptionError):
    """Raised when an unsupported file type is encountered."""
    pass


@dataclass
class EncryptionConfig:
    """Configuration class for encryption parameters."""
    pbkdf2_iterations: int = 100_000  # OWASP recommended minimum
    salt_length: int = 32  # 256 bits
    chunk_size: int = 64 * 1024  # 64KB chunks for memory efficiency
    backup_original: bool = False  # Disabled for web interface
    verify_integrity: bool = True
    log_operations: bool = False  # Disabled for web interface
    max_file_size: int = 100 * 1024 * 1024  # 100MB default limit
    
    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        if self.pbkdf2_iterations < 10_000:
            raise ValueError("PBKDF2 iterations must be at least 10,000 for security")
        if self.salt_length < 16:
            raise ValueError("Salt length must be at least 16 bytes")
        if self.chunk_size < 1024:
            raise ValueError("Chunk size must be at least 1024 bytes")


@dataclass
class EncryptionMetadata:
    """Metadata for encrypted files."""
    version: str = "1.0"
    algorithm: str = "Fernet"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    file_hash: Optional[str] = None
    iterations: int = 100_000
    salt_length: int = 32
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            'version': self.version,
            'algorithm': self.algorithm,
            'timestamp': self.timestamp,
            'file_hash': self.file_hash,
            'iterations': self.iterations,
            'salt_length': self.salt_length
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptionMetadata':
        """Create metadata from dictionary."""
        return cls(**data)


class FileEncryptionTool:
    """Enterprise-grade file encryption tool using Fernet symmetric encryption."""
    
    def __init__(self, config: Optional[EncryptionConfig] = None):
        """Initialize the encryption tool."""
        self.config = config or EncryptionConfig()
        self._validate_environment()
    
    def _validate_environment(self) -> None:
        """Validate the runtime environment."""
        try:
            # Test cryptography functionality
            test_key = Fernet.generate_key()
            test_fernet = Fernet(test_key)
            test_data = b"test"
            encrypted = test_fernet.encrypt(test_data)
            decrypted = test_fernet.decrypt(encrypted)
            assert decrypted == test_data
        except Exception as e:
            raise FileEncryptionError(f"Cryptography validation failed: {e}")
    
    def _generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt."""
        return secrets.token_bytes(self.config.salt_length)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for Fernet
                salt=salt,
                iterations=self.config.pbkdf2_iterations,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
            return key
        except Exception as e:
            raise FileEncryptionError(f"Key derivation failed: {e}")
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file for integrity verification."""
        hash_sha256 = hashlib.sha256()
        try:
            with file_path.open('rb') as f:
                for chunk in iter(lambda: f.read(self.config.chunk_size), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            raise FileEncryptionError(f"Hash calculation failed: {e}")
    
    def _validate_file_access(self, file_path: Path, operation: str) -> None:
        """Validate file access permissions and constraints."""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not file_path.is_file():
            raise UnsupportedFileTypeError(f"Path is not a regular file: {file_path}")
        
        # Check file size limits
        file_size = file_path.stat().st_size
        if file_size > self.config.max_file_size:
            raise FileEncryptionError(
                f"File size ({file_size} bytes) exceeds maximum allowed "
                f"({self.config.max_file_size} bytes)"
            )
        
        # Check permissions
        if operation == 'read' and not os.access(file_path, os.R_OK):
            raise InsufficientPermissionsError(f"No read permission for: {file_path}")
        elif operation == 'write' and not os.access(file_path.parent, os.W_OK):
            raise InsufficientPermissionsError(f"No write permission for: {file_path.parent}")
    
    def encrypt_file(self, file_path: Union[str, Path], password: str, 
                    output_path: Optional[Union[str, Path]] = None) -> Path:
        """Encrypt a file using Fernet symmetric encryption."""
        file_path = Path(file_path)
        output_path = Path(output_path) if output_path else file_path.with_suffix(file_path.suffix + '.encrypted')
        
        # Validation
        self._validate_file_access(file_path, 'read')
        if not password.strip():
            raise InvalidPasswordError("Password cannot be empty")
        
        try:
            # Generate salt and derive key
            salt = self._generate_salt()
            key = self._derive_key(password, salt)
            fernet = Fernet(key)
            
            # Calculate original file hash for integrity
            original_hash = None
            if self.config.verify_integrity:
                original_hash = self._calculate_file_hash(file_path)
            
            # Create metadata
            metadata = EncryptionMetadata(
                file_hash=original_hash,
                iterations=self.config.pbkdf2_iterations,
                salt_length=self.config.salt_length
            )
            
            # Encrypt file in chunks
            with file_path.open('rb') as infile, output_path.open('wb') as outfile:
                # Write salt and metadata
                metadata_json = json.dumps(metadata.to_dict()).encode('utf-8')
                metadata_length = len(metadata_json)
                
                outfile.write(metadata_length.to_bytes(4, 'big'))
                outfile.write(metadata_json)
                outfile.write(salt)
                
                # Encrypt file content in chunks
                while True:
                    chunk = infile.read(self.config.chunk_size)
                    if not chunk:
                        break
                    
                    encrypted_chunk = fernet.encrypt(chunk)
                    chunk_length = len(encrypted_chunk)
                    outfile.write(chunk_length.to_bytes(4, 'big'))
                    outfile.write(encrypted_chunk)
            
            return output_path
            
        except Exception as e:
            # Clean up partial output file
            if output_path.exists():
                try:
                    output_path.unlink()
                except:
                    pass
            
            if isinstance(e, FileEncryptionError):
                raise
            else:
                raise FileEncryptionError(f"Encryption failed: {e}")
    
    def decrypt_file(self, encrypted_path: Union[str, Path], password: str,
                    output_path: Optional[Union[str, Path]] = None) -> Path:
        """Decrypt a file encrypted with this tool."""
        encrypted_path = Path(encrypted_path)
        
        if output_path:
            output_path = Path(output_path)
        else:
            # Remove .encrypted extension to restore original filename
            if encrypted_path.name.endswith('.encrypted'):
                original_name = encrypted_path.name[:-10]  # Remove '.encrypted'
                output_path = encrypted_path.parent / original_name
            else:
                output_path = encrypted_path.parent / (encrypted_path.stem + '_decrypted' + encrypted_path.suffix)
        
        # Validation
        self._validate_file_access(encrypted_path, 'read')
        if not password.strip():
            raise InvalidPasswordError("Password cannot be empty")
        
        try:
            with encrypted_path.open('rb') as infile:
                # Read metadata
                metadata_length_bytes = infile.read(4)
                if len(metadata_length_bytes) != 4:
                    raise CorruptedFileError("Invalid file format: missing metadata length")
                
                metadata_length = int.from_bytes(metadata_length_bytes, 'big')
                metadata_json = infile.read(metadata_length)
                
                try:
                    metadata_dict = json.loads(metadata_json.decode('utf-8'))
                    metadata = EncryptionMetadata.from_dict(metadata_dict)
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    raise CorruptedFileError(f"Invalid metadata: {e}")
                
                # Read salt
                salt = infile.read(metadata.salt_length)
                if len(salt) != metadata.salt_length:
                    raise CorruptedFileError("Invalid salt length")
                
                # Derive key
                key = self._derive_key(password, salt)
                fernet = Fernet(key)
                
                # Decrypt file content
                with output_path.open('wb') as outfile:
                    while True:
                        chunk_length_bytes = infile.read(4)
                        if len(chunk_length_bytes) != 4:
                            break  # End of file
                        
                        chunk_length = int.from_bytes(chunk_length_bytes, 'big')
                        encrypted_chunk = infile.read(chunk_length)
                        
                        if len(encrypted_chunk) != chunk_length:
                            raise CorruptedFileError("Incomplete encrypted chunk")
                        
                        try:
                            decrypted_chunk = fernet.decrypt(encrypted_chunk)
                            outfile.write(decrypted_chunk)
                        except InvalidToken:
                            raise InvalidPasswordError("Incorrect password or corrupted file")
            
            # Verify file integrity if enabled
            if self.config.verify_integrity and metadata.file_hash:
                calculated_hash = self._calculate_file_hash(output_path)
                if calculated_hash != metadata.file_hash:
                    output_path.unlink()  # Remove corrupted output
                    raise CorruptedFileError("File integrity check failed")
            
            return output_path
            
        except Exception as e:
            # Clean up partial output file
            if output_path.exists():
                try:
                    output_path.unlink()
                except:
                    pass
            
            if isinstance(e, FileEncryptionError):
                raise
            else:
                raise FileEncryptionError(f"Decryption failed: {e}")
    
    def verify_file_integrity(self, encrypted_path: Union[str, Path]) -> bool:
        """Verify the integrity of an encrypted file without decrypting it."""
        encrypted_path = Path(encrypted_path)
        
        try:
            self._validate_file_access(encrypted_path, 'read')
            
            with encrypted_path.open('rb') as infile:
                # Read and validate metadata
                metadata_length_bytes = infile.read(4)
                if len(metadata_length_bytes) != 4:
                    return False
                
                metadata_length = int.from_bytes(metadata_length_bytes, 'big')
                metadata_json = infile.read(metadata_length)
                
                try:
                    metadata_dict = json.loads(metadata_json.decode('utf-8'))
                    metadata = EncryptionMetadata.from_dict(metadata_dict)
                except:
                    return False
                
                # Check salt
                salt = infile.read(metadata.salt_length)
                if len(salt) != metadata.salt_length:
                    return False
                
                # Validate chunk structure
                while True:
                    chunk_length_bytes = infile.read(4)
                    if len(chunk_length_bytes) != 4:
                        break
                    
                    chunk_length = int.from_bytes(chunk_length_bytes, 'big')
                    chunk = infile.read(chunk_length)
                    
                    if len(chunk) != chunk_length:
                        return False
                
                return True
                
        except Exception:
            return False


# ===== STREAMLIT UI =====

# Configure Streamlit page
st.set_page_config(
    page_title="🔐 File Encryption Tool",
    page_icon="🔐",
    layout="wide"
)

# Initialize session state
if 'encryption_tool' not in st.session_state:
    # Create encryption tool with default config
    config = EncryptionConfig(
        pbkdf2_iterations=100_000,
        backup_original=False,
        verify_integrity=True,
        log_operations=False
    )
    st.session_state['encryption_tool'] = FileEncryptionTool(config=config)


def main():
    st.title("🔐 File Encryption Tool")
    st.markdown("**Secure file encryption using enterprise-grade algorithms**")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Security settings
        iterations = st.slider(
            "PBKDF2 Iterations",
            min_value=10000,
            max_value=500000,
            value=100000,
            step=10000,
            help="Higher values are more secure but slower"
        )
        
        verify_integrity = st.checkbox(
            "Verify File Integrity",
            value=True,
            help="Verify file hasn't been corrupted after encryption/decryption"
        )
        
        # Update config if changed
        current_config = st.session_state['encryption_tool'].config
        if (iterations != current_config.pbkdf2_iterations or 
            verify_integrity != current_config.verify_integrity):
            
            new_config = EncryptionConfig(
                pbkdf2_iterations=iterations,
                backup_original=False,
                verify_integrity=verify_integrity,
                log_operations=False
            )
            st.session_state['encryption_tool'] = FileEncryptionTool(config=new_config)
            st.success("Configuration updated!")
    
    # Main interface tabs
    tab1, tab2, tab3 = st.tabs(["🔒 Encrypt File", "🔓 Decrypt File", "ℹ️ File Info"])
    
    with tab1:
        encrypt_file_interface()
    
    with tab2:
        decrypt_file_interface()
    
    with tab3:
        file_info_interface()


def encrypt_file_interface():
    st.header("🔒 Encrypt File")
    st.write("Upload a file and provide a password to encrypt it securely.")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose a file to encrypt",
        type=None,  # Allow all file types
        help="Maximum file size: 100MB"
    )
    
    if uploaded_file is not None:
        # Display file info
        file_size_mb = len(uploaded_file.getvalue()) / (1024 * 1024)
        st.info(f"📁 File: {uploaded_file.name} ({file_size_mb:.2f} MB)")
        
        if file_size_mb > 100:
            st.error("❌ File size exceeds 100MB limit!")
            return
        
        # Password input
        password = st.text_input(
            "Enter encryption password",
            type="password",
            help="Choose a strong password. You'll need this to decrypt the file later."
        )
        
        password_confirm = st.text_input(
            "Confirm encryption password",
            type="password"
        )
        
        if st.button("🔒 Encrypt File", type="primary"):
            if not password:
                st.error("❌ Please enter a password!")
                return
            
            if password != password_confirm:
                st.error("❌ Passwords don't match!")
                return
            
            if len(password) < 6:
                st.warning("⚠️ Password is quite short. Consider using a longer password for better security.")
            
            try:
                # Create temporary files
                with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as temp_input:
                    temp_input.write(uploaded_file.getvalue())
                    temp_input_path = Path(temp_input.name)
                
                with st.spinner("🔄 Encrypting file..."):
                    # Encrypt the file
                    encrypted_path = st.session_state['encryption_tool'].encrypt_file(
                        temp_input_path,
                        password
                    )
                    
                    # Read encrypted file
                    encrypted_data = encrypted_path.read_bytes()
                    
                    st.success("✅ File encrypted successfully!")
                    
                    # Download button
                    st.download_button(
                        label="📥 Download Encrypted File",
                        data=encrypted_data,
                        file_name=f"{uploaded_file.name}.encrypted",
                        mime="application/octet-stream",
                        help="Save this encrypted file. You'll need your password to decrypt it."
                    )
                    
                    # Security reminder
                    st.warning("🔑 **Important**: Remember your password! Without it, you cannot decrypt the file.")
                
                # Cleanup
                temp_input_path.unlink(missing_ok=True)
                encrypted_path.unlink(missing_ok=True)
                
            except InvalidPasswordError as e:
                st.error(f"❌ Password Error: {e}")
            except FileEncryptionError as e:
                st.error(f"❌ Encryption Error: {e}")
            except Exception as e:
                st.error(f"❌ Unexpected Error: {e}")
                st.error("Please try again or contact support.")


def decrypt_file_interface():
    st.header("🔓 Decrypt File")
    st.write("Upload an encrypted file and provide the password to decrypt it.")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose an encrypted file to decrypt",
        type=["encrypted"],
        help="Select a .encrypted file created by this tool"
    )
    
    if uploaded_file is not None:
        # Display file info
        file_size_mb = len(uploaded_file.getvalue()) / (1024 * 1024)
        st.info(f"📁 Encrypted File: {uploaded_file.name} ({file_size_mb:.2f} MB)")
        
        # Password input
        password = st.text_input(
            "Enter decryption password",
            type="password",
            help="Enter the same password used to encrypt this file"
        )
        
        if st.button("🔓 Decrypt File", type="primary"):
            if not password:
                st.error("❌ Please enter the decryption password!")
                return
            
            try:
                # Create temporary files
                with tempfile.NamedTemporaryFile(delete=False, suffix=".encrypted") as temp_encrypted:
                    temp_encrypted.write(uploaded_file.getvalue())
                    temp_encrypted_path = Path(temp_encrypted.name)
                
                with st.spinner("🔄 Decrypting file..."):
                    # Decrypt the file
                    decrypted_path = st.session_state['encryption_tool'].decrypt_file(
                        temp_encrypted_path,
                        password
                    )
                    
                    # Read decrypted file
                    decrypted_data = decrypted_path.read_bytes()
                    
                    st.success("✅ File decrypted successfully!")
                    
                    # Determine original filename
                    original_name = uploaded_file.name
                    if original_name.endswith('.encrypted'):
                        original_name = original_name[:-10]  # Remove .encrypted
                    
                    # Download button
                    st.download_button(
                        label="📥 Download Decrypted File",
                        data=decrypted_data,
                        file_name=original_name,
                        mime="application/octet-stream"
                    )
                
                # Cleanup
                temp_encrypted_path.unlink(missing_ok=True)
                decrypted_path.unlink(missing_ok=True)
                
            except InvalidPasswordError:
                st.error("❌ **Incorrect Password**: The password you entered is wrong or the file is corrupted.")
            except CorruptedFileError as e:
                st.error(f"❌ **File Corrupted**: {e}")
            except FileEncryptionError as e:
                st.error(f"❌ Decryption Error: {e}")
            except Exception as e:
                st.error(f"❌ Unexpected Error: {e}")
                st.error("Please check that the file is a valid encrypted file created by this tool.")


def file_info_interface():
    st.header("ℹ️ File Information & Verification")
    st.write("Check information about encrypted files and verify their integrity.")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose an encrypted file to analyze",
        type=["encrypted"],
        help="Select a .encrypted file to view its metadata"
    )
    
    if uploaded_file is not None:
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".encrypted") as temp_file:
                temp_file.write(uploaded_file.getvalue())
                temp_file_path = Path(temp_file.name)
            
            # Verify file integrity
            with st.spinner("🔍 Analyzing file..."):
                is_valid = st.session_state['encryption_tool'].verify_file_integrity(temp_file_path)
            
            # Display results
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("File Size", f"{len(uploaded_file.getvalue()) / 1024:.1f} KB")
                
                if is_valid:
                    st.success("✅ File structure is valid")
                else:
                    st.error("❌ File structure is invalid or corrupted")
            
            with col2:
                st.metric("File Name", uploaded_file.name)
                st.info("🔐 File is encrypted with enterprise-grade security")
            
            # Additional info
            st.subheader("🛡️ Security Features")
            config = st.session_state['encryption_tool'].config
            
            security_info = f"""
            - **Algorithm**: Fernet (AES 128 in CBC mode with HMAC-SHA256)
            - **Key Derivation**: PBKDF2 with {config.pbkdf2_iterations:,} iterations
            - **Salt Length**: {config.salt_length} bytes
            - **Integrity Verification**: {'Enabled' if config.verify_integrity else 'Disabled'}
            """
            
            st.markdown(security_info)
            
            # Cleanup
            temp_file_path.unlink(missing_ok=True)
            
        except Exception as e:
            st.error(f"❌ Error analyzing file: {e}")


if __name__ == "__main__":
    main()
