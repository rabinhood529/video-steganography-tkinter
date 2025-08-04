"""
Encryption Utilities
Provides password-based encryption and decryption for secret files.
"""

import os
import hashlib
import logging
from typing import Tuple, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)


class PasswordEncryption:
    """Password-based encryption using Fernet (AES 128)"""
    
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: User password
            salt: Random salt bytes
            
        Returns:
            Derived key bytes
        """
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    @staticmethod
    def encrypt_data(data: bytes, password: str) -> bytes:
        """
        Encrypt data with password
        
        Args:
            data: Data to encrypt
            password: Password for encryption
            
        Returns:
            Encrypted data with salt prepended
        """
        try:
            # Generate random salt
            salt = os.urandom(16)
            
            # Derive key from password
            key = PasswordEncryption._derive_key(password, salt)
            
            # Create Fernet cipher
            fernet = Fernet(key)
            
            # Encrypt data
            encrypted_data = fernet.encrypt(data)
            
            # Prepend salt to encrypted data
            result = salt + encrypted_data
            
            logger.info(f"Successfully encrypted {len(data)} bytes")
            return result
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
        """
        Decrypt data with password
        
        Args:
            encrypted_data: Encrypted data with salt prepended
            password: Password for decryption
            
        Returns:
            Decrypted data
        """
        try:
            if len(encrypted_data) < 16:
                raise ValueError("Invalid encrypted data format")
            
            # Extract salt and encrypted data
            salt = encrypted_data[:16]
            encrypted_content = encrypted_data[16:]
            
            # Derive key from password
            key = PasswordEncryption._derive_key(password, salt)
            
            # Create Fernet cipher
            fernet = Fernet(key)
            
            # Decrypt data
            decrypted_data = fernet.decrypt(encrypted_content)
            
            logger.info(f"Successfully decrypted {len(decrypted_data)} bytes")
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    @staticmethod
    def encrypt_file(file_path: str, password: str, output_path: Optional[str] = None) -> str:
        """
        Encrypt a file with password
        
        Args:
            file_path: Path to file to encrypt
            password: Password for encryption
            output_path: Optional output path (defaults to file_path + '.enc')
            
        Returns:
            Path to encrypted file
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt data
            encrypted_data = PasswordEncryption.encrypt_data(file_data, password)
            
            # Determine output path
            if output_path is None:
                output_path = file_path + '.enc'
            
            # Write encrypted file
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            logger.info(f"File encrypted: {file_path} -> {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            raise
    
    @staticmethod
    def decrypt_file(encrypted_file_path: str, password: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt a file with password
        
        Args:
            encrypted_file_path: Path to encrypted file
            password: Password for decryption
            output_path: Optional output path (defaults to removing '.enc' extension)
            
        Returns:
            Path to decrypted file
        """
        try:
            if not os.path.exists(encrypted_file_path):
                raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")
            
            # Read encrypted data
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt data
            decrypted_data = PasswordEncryption.decrypt_data(encrypted_data, password)
            
            # Determine output path
            if output_path is None:
                if encrypted_file_path.endswith('.enc'):
                    output_path = encrypted_file_path[:-4]  # Remove '.enc'
                else:
                    output_path = encrypted_file_path + '.dec'
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"File decrypted: {encrypted_file_path} -> {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            raise
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """
        Validate password strength
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) > 128:
            return False, "Password too long (max 128 characters)"
        
        # Check for at least one uppercase, lowercase, and digit
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        if not (has_upper and has_lower and has_digit):
            return False, "Password must contain uppercase, lowercase, and digit"
        
        return True, "Password is strong"
    
    @staticmethod
    def generate_password_hash(password: str) -> str:
        """
        Generate a hash of the password for verification
        
        Args:
            password: Password to hash
            
        Returns:
            SHA-256 hash of password
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()


class SecureFileHandler:
    """Secure file handling with optional encryption"""
    
    def __init__(self, password: Optional[str] = None):
        """
        Initialize with optional password
        
        Args:
            password: Optional password for encryption
        """
        self.password = password
        self.encryption_enabled = password is not None
        
        if self.encryption_enabled:
            is_valid, message = PasswordEncryption.validate_password(password)
            if not is_valid:
                raise ValueError(f"Invalid password: {message}")
    
    def prepare_secret_data(self, file_path: str) -> bytes:
        """
        Prepare secret file data for embedding (with optional encryption)
        
        Args:
            file_path: Path to secret file
            
        Returns:
            Processed file data (encrypted if password provided)
        """
        try:
            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Add file metadata
            file_name = os.path.basename(file_path)
            file_ext = os.path.splitext(file_path)[1]
            
            # Create metadata header
            metadata = f"{len(file_data)}|{file_name}|{file_ext}|".encode('utf-8')
            
            # Combine metadata and file data
            combined_data = metadata + file_data
            
            # Encrypt if password provided
            if self.encryption_enabled:
                combined_data = PasswordEncryption.encrypt_data(combined_data, self.password)
                # Add encryption marker
                combined_data = b"ENCRYPTED|" + combined_data
            
            logger.info(f"Prepared secret data: {len(combined_data)} bytes")
            return combined_data
            
        except Exception as e:
            logger.error(f"Failed to prepare secret data: {e}")
            raise
    
    def extract_secret_data(self, extracted_data: bytes, output_path: str) -> str:
        """
        Extract and save secret file data (with optional decryption)
        
        Args:
            extracted_data: Raw extracted data
            output_path: Base path for output file
            
        Returns:
            Path to extracted file
        """
        try:
            processed_data = extracted_data
            
            # Check for encryption marker
            if processed_data.startswith(b"ENCRYPTED|"):
                if not self.encryption_enabled:
                    raise ValueError("Data is encrypted but no password provided")
                
                # Remove marker and decrypt
                encrypted_data = processed_data[10:]  # Remove "ENCRYPTED|"
                processed_data = PasswordEncryption.decrypt_data(encrypted_data, self.password)
            
            # Parse metadata header
            header_end = processed_data.find(b"|", processed_data.find(b"|", processed_data.find(b"|") + 1) + 1)
            if header_end == -1:
                raise ValueError("Invalid data format - missing metadata")
            
            header = processed_data[:header_end + 1].decode('utf-8')
            file_data = processed_data[header_end + 1:]
            
            # Parse header components
            parts = header.split('|')
            if len(parts) < 3:
                raise ValueError("Invalid metadata format")
            
            file_size = int(parts[0])
            file_name = parts[1]
            file_ext = parts[2]
            
            # Validate file size
            if len(file_data) != file_size:
                logger.warning(f"File size mismatch: expected {file_size}, got {len(file_data)}")
            
            # Determine output file path
            base_name = os.path.splitext(os.path.basename(output_path))[0]
            output_dir = os.path.dirname(output_path)
            final_output_path = os.path.join(output_dir, f"{base_name}_{file_name}")
            
            # Write extracted file
            with open(final_output_path, 'wb') as f:
                f.write(file_data)
            
            logger.info(f"Extracted secret file: {final_output_path}")
            return final_output_path
            
        except Exception as e:
            logger.error(f"Failed to extract secret data: {e}")
            raise