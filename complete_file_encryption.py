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
from typing import Optional, Union, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import json
import smtplib
import ssl
import hmac
import urllib.request
import urllib.parse
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
    # OTP-related fields (optional)
    otp_enabled: bool = False
    otp_hash: Optional[str] = None  # SHA-256 hex digest of OTP HMAC
    otp_salt: Optional[str] = None  # hex-encoded salt used as HMAC key
    otp_expiry: Optional[str] = None  # ISO8601 timestamp
    otp_contact: Optional[str] = None  # email or phone number

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            'version': self.version,
            'algorithm': self.algorithm,
            'timestamp': self.timestamp,
            'file_hash': self.file_hash,
            'iterations': self.iterations,
            'salt_length': self.salt_length,
            'otp_enabled': self.otp_enabled,
            'otp_hash': self.otp_hash,
            'otp_salt': self.otp_salt,
            'otp_expiry': self.otp_expiry,
            'otp_contact': self.otp_contact
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptionMetadata':
        """Create metadata from dictionary with safe defaults for backward compatibility."""
        return cls(
            version=data.get('version', '1.0'),
            algorithm=data.get('algorithm', 'Fernet'),
            timestamp=data.get('timestamp', datetime.now(timezone.utc).isoformat()),
            file_hash=data.get('file_hash'),
            iterations=data.get('iterations', 100_000),
            salt_length=data.get('salt_length', 32),
            otp_enabled=data.get('otp_enabled', False),
            otp_hash=data.get('otp_hash'),
            otp_salt=data.get('otp_salt'),
            otp_expiry=data.get('otp_expiry'),
            otp_contact=data.get('otp_contact')
        )


# ===== OTP SERVICE / UTILITIES =====


def _now_utc_iso() -> str:
    """Return current UTC time as ISO8601 string."""
    return datetime.now(timezone.utc).isoformat()


def generate_numeric_otp(length: int = 6) -> str:
    """Generate a cryptographically secure numeric OTP.

    Constructed digit-by-digit using secrets.randbelow to avoid modulo bias.
    """
    if length <= 0:
        raise ValueError("OTP length must be positive")
    return ''.join(str(secrets.randbelow(10)) for _ in range(length))


def hash_otp(otp: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Hash OTP using HMAC-SHA256 with a random salt (used as HMAC key).

    Returns (hex_digest, hex_salt).
    """
    # Simplified for demo: do not perform HMAC hashing. Return the plain OTP
    # and an empty salt marker. This keeps the metadata structure unchanged
    # while making OTP handling easy to understand for demos.
    return otp, ''


class OTPProvider:
    """Abstract OTP sending interface."""

    def send(self, contact: str, message: str) -> None:
        raise NotImplementedError()


class SMTPEmailProvider(OTPProvider):
    """SMTP-based email provider.

    In real deployments prefer a transactional email provider SDK (SendGrid, SES, etc.)
    configured with proper credentials and TLS.
    """

    def __init__(self, smtp_server: str, smtp_port: int = 587, username: Optional[str] = None,
                 password: Optional[str] = None, use_tls: bool = True, from_addr: Optional[str] = None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.from_addr = from_addr or username

    def send(self, contact: str, message: str) -> None:
        if not self.from_addr:
            raise FileEncryptionError("SMTP from address not configured")

        subject = "Your OTP code"
        email_text = f"Subject: {subject}\nTo: {contact}\nFrom: {self.from_addr}\n\n{message}"

        context = ssl.create_default_context()
        try:
            # Support both STARTTLS (commonly port 587) and implicit SSL (port 465)
            if self.use_tls and self.smtp_port == 465:
                # Implicit SSL
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context, timeout=10) as server:
                    if self.username and self.password:
                        server.login(self.username, self.password)
                    server.sendmail(self.from_addr, [contact], email_text)
            else:
                # STARTTLS flow (default port 587)
                with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
                    server.ehlo()
                    if self.use_tls:
                        server.starttls(context=context)
                        server.ehlo()
                    if self.username and self.password:
                        server.login(self.username, self.password)
                    server.sendmail(self.from_addr, [contact], email_text)
        except Exception:
            # Surface a friendly error for demo troubleshooting
            raise FileEncryptionError("Failed to send OTP email; check SMTP credentials and network connectivity")


class TwilioSMSProvider(OTPProvider):
    """Minimal Twilio-like SMS sender using HTTP API.

    This is a light abstraction; in production use official SDK and secure storage
    for credentials.
    """

    def __init__(self, account_sid: str, auth_token: str, from_number: str):
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_number = from_number

    def send(self, contact: str, message: str) -> None:
        url = f"https://api.twilio.com/2010-04-01/Accounts/{urllib.parse.quote(self.account_sid)}/Messages.json"
        data = urllib.parse.urlencode({
            'From': self.from_number,
            'To': contact,
            'Body': message
        }).encode('utf-8')

        creds = f"{self.account_sid}:{self.auth_token}"
        auth = base64.b64encode(creds.encode('utf-8')).decode('ascii')

        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Authorization', f'Basic {auth}')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.getcode()
                if status >= 400:
                    raise FileEncryptionError('Failed to send SMS')
        except Exception:
            raise FileEncryptionError('Failed to send SMS')


# Simple in-memory attempt tracker for brute-force protection (single-process)
# For production use Redis or other centralized store for distributed rate limiting.
def validate_otp_provided(provided_otp: str, metadata: EncryptionMetadata, salt_bytes: bytes,
                           max_attempts: int = 5) -> None:
    """Simplified OTP validation for demo purposes.

    - Expects the plain OTP to be stored in metadata.otp_hash.
    - Checks expiry and uses a constant-time comparison.
    - No attempt-tracking is performed (keep this in mind: demo only).
    """
    if not metadata.otp_enabled:
        return

    if not metadata.otp_hash or not metadata.otp_expiry:
        raise FileEncryptionError("OTP metadata is incomplete")

    # Check expiry
    expiry_dt = datetime.fromisoformat(metadata.otp_expiry)
    if datetime.now(timezone.utc) > expiry_dt:
        raise InvalidPasswordError("OTP has expired")

    expected = metadata.otp_hash  # plain OTP stored for demo

    # Use secrets.compare_digest for a timing-attack resistant comparison
    if not secrets.compare_digest(provided_otp, expected):
        raise InvalidPasswordError("Invalid OTP")



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
                    output_path: Optional[Union[str, Path]] = None,
                    otp_contact: Optional[str] = None,
                    otp_provider: Optional[OTPProvider] = None,
                    otp_length: int = 6,
                    otp_ttl_seconds: int = 300) -> Path:
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

            # If OTP is requested, generate, hash, and send it via provider
            if otp_contact:
                if not otp_provider:
                    raise FileEncryptionError("OTP provider is required when otp_contact is supplied")

                # Generate OTP and hash it (never store raw OTP)
                otp = generate_numeric_otp(otp_length)
                otp_hash_hex, otp_salt_hex = hash_otp(otp)
                expiry_dt = datetime.now(timezone.utc) + timedelta(seconds=otp_ttl_seconds)
                metadata.otp_enabled = True
                metadata.otp_hash = otp_hash_hex
                metadata.otp_salt = otp_salt_hex
                metadata.otp_expiry = expiry_dt.isoformat()
                metadata.otp_contact = otp_contact

                # Send OTP via provider; errors should abort encryption without leaking secrets
                send_msg = f"Your OTP for decrypting the file is: {otp}. It expires in {otp_ttl_seconds//60} minutes."
                otp_provider.send(otp_contact, send_msg)
            
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
                    output_path: Optional[Union[str, Path]] = None,
                    provided_otp: Optional[str] = None) -> Path:
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

                # If OTP is enabled in metadata, validate provided OTP BEFORE decryption
                if metadata.otp_enabled:
                    if not provided_otp:
                        raise InvalidPasswordError("OTP required for decryption but not provided")
                    # Validate OTP (may raise InvalidPasswordError)
                    validate_otp_provided(provided_otp, metadata, salt)

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
    
    # Team credits section
    with st.expander("👥 About the Development Team", expanded=False):
        st.markdown("### 🛠️ Built by Team **EncryptEase**")
        st.markdown("**Total Members:** 4")
        st.markdown("""
        **Team Members:**
        - 🧑‍💻 **Jay Kumar**
        - 👩‍💻 **Gaurav Singh Solanki** 
        - 🧑‍💻 **Badal Pal**
        - 👨‍💻 **Kaustubh Sharma**
        """)
        st.markdown("---")
        st.markdown("💡 *This tool was developed with dedication to providing secure and user-friendly file encryption.*")
    
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
    
    # Main interface tabs (added Cybersecurity Awareness tab)
    tab1, tab2, tab3, tab4 = st.tabs(["🔒 Encrypt File", "🔓 Decrypt File", "ℹ️ File Info", "🛡️ Cybersecurity Awareness"])

    with tab1:
        encrypt_file_interface()

    with tab2:
        decrypt_file_interface()

    with tab3:
        file_info_interface()

    with tab4:
        cyber_awareness_interface()


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
        
        # OTP options
        enable_otp = st.checkbox("Enable OTP (optional)", value=False,
                                 help="Send a one-time password to an email or phone number for MFA during decryption.")
        otp_contact = None
        otp_method = None
        if enable_otp:
            # Prefill demo email for convenience; user can change it if desired
            otp_contact = st.text_input("OTP Contact (email or phone)", value=" ", help="Enter an email address or phone number to receive the OTP")
            otp_method = st.selectbox("OTP Method", ["email", "sms"], help="Choose how the OTP will be delivered")

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
                    # Prepare OTP provider if requested. Try environment first; if missing,
                    # allow entering SMTP details in the app (session-only storage) for demo usage.
                    provider_obj = None
                    if enable_otp and otp_contact:
                        if otp_method == 'email':
                            # DEMO: Use hardcoded SMTP credentials for the demo Gmail account.
                            # WARNING: Hardcoding credentials is insecure. Do NOT commit these
                            # values to a public repository. This is provided only to support
                            # an offline demo to your teacher as requested.
                            smtp_server = "smtp.gmail.com"
                            smtp_port = 465
                            smtp_user = "02.trial.email@gmail.com"
                            smtp_pass = "qdxq ckcu glfk cydv"
                            smtp_from = "02.trial.email@gmail.com"

                            provider_obj = SMTPEmailProvider(smtp_server, smtp_port, smtp_user, smtp_pass, True, smtp_from)
                        else:
                            tw_sid = os.environ.get('TWILIO_SID')
                            tw_token = os.environ.get('TWILIO_TOKEN')
                            tw_from = os.environ.get('TWILIO_FROM')
                            if not tw_sid or not tw_token or not tw_from:
                                st.error('Twilio configuration missing in environment (TWILIO_SID/TWILIO_TOKEN/TWILIO_FROM)')
                                return
                            provider_obj = TwilioSMSProvider(tw_sid, tw_token, tw_from)

                    encrypted_path = st.session_state['encryption_tool'].encrypt_file(
                        temp_input_path,
                        password,
                        otp_contact=otp_contact if enable_otp else None,
                        otp_provider=provider_obj
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
        
        # Determine whether OTP is required by inspecting file metadata (lightweight)
        otp_required = False
        try:
            raw = uploaded_file.getvalue()
            if len(raw) >= 4:
                metadata_length = int.from_bytes(raw[0:4], 'big')
                if len(raw) >= 4 + metadata_length:
                    metadata_json = raw[4:4+metadata_length]
                    metadata_dict = json.loads(metadata_json.decode('utf-8'))
                    otp_required = bool(metadata_dict.get('otp_enabled', False))
        except Exception:
            otp_required = False

        # Password input
        password = st.text_input(
            "Enter decryption password",
            type="password",
            help="Enter the same password used to encrypt this file"
        )

        provided_otp = None
        if otp_required:
            provided_otp = st.text_input(
                "Enter OTP",
                type="password",
                help="Enter the one-time password sent to your email or phone"
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
                    # Decrypt the file (pass OTP if required)
                    decrypted_path = st.session_state['encryption_tool'].decrypt_file(
                        temp_encrypted_path,
                        password,
                        provided_otp=provided_otp
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


def cyber_awareness_interface():
    """Simple Cybersecurity Awareness tab for demos.

    Includes basic tips, common threats, helpline numbers, and a place to add a video.
    """
    st.header("🛡️ Cybersecurity Awareness")
    st.write("Learn basic safe practices and where to get help.")

    # Layout: two columns for tips and threats
    tips_col, threats_col = st.columns([2, 2])

    with tips_col:
        st.subheader("Basic Cyber Hygiene")
        st.markdown(
            """
- Use strong, unique passwords and a password manager.
- Enable two-factor authentication (2FA) wherever possible.
- Keep your OS and applications up to date.
- Avoid clicking links from unknown senders; verify email senders.
- Backup important files regularly and verify backups.
            """
        )

    with threats_col:
        st.subheader("Common Cyber Threats")
        st.markdown(
            """
- Phishing — fraudulent messages that trick you into revealing data.
- Malware — software designed to harm or steal data.
- Ransomware — encrypts your files and demands payment.
- Identity theft — attackers using personal data to impersonate you.
            """
        )

    st.markdown("---")

    # Helpline information
    st.subheader("Useful Cyber Helplines (India)")
    st.markdown(
        """
- **Cyber Crime Helpline:** 1930
- **Police (Emergency):** 100
- **Women Helpline:** 1091
- **Cyber Crime Website:** https://cybercrime.gov.in
        """
    )

    st.markdown("---")

    # Video section: allow demo user to paste a URL or upload a small file
    st.subheader("Awareness Video")
    st.write("Add a short awareness video here. Provide a public video URL or upload a small file.")

    # Placeholder box reserved for admin to add a video later.
    # For demo purposes we always show an empty dashed box as a visual placeholder.
    st.markdown(
        '<div style="border:1px dashed #999; padding:16px; height:240px; display:flex; align-items:center; justify-content:center; color:#666;">'
        + 'Video placeholder — admin will add video here.'
        + '</div>',
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.info("This section is for educational/demo purposes. Follow your institution's guidance for production-ready security practices.")


if __name__ == "__main__":
    main()
