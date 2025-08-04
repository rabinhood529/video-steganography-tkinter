"""
Encryption and decryption functionality for secret files.
"""

import os
import hashlib
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from utils.logger import get_logger

logger = get_logger(__name__)


class FileEncryption:
    """Handles AES-256 encryption and decryption of files."""
    
    SALT_LENGTH = 16
    IV_LENGTH = 16
    KEY_LENGTH = 32  # 256 bits
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Random salt bytes
            
        Returns:
            Derived key bytes
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=FileEncryption.KEY_LENGTH,
                salt=salt,
                iterations=100000,  # OWASP recommended minimum
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error deriving key: {e}")
            raise
    
    @staticmethod
    def encrypt_data(data: bytes, password: str) -> Optional[bytes]:
        """
        Encrypt data using AES-256-CBC.
        
        Args:
            data: Data to encrypt
            password: Encryption password
            
        Returns:
            Encrypted data with salt and IV prepended, or None if error
        """
        try:
            # Generate random salt and IV
            salt = os.urandom(FileEncryption.SALT_LENGTH)
            iv = os.urandom(FileEncryption.IV_LENGTH)
            
            # Derive key from password
            key = FileEncryption.derive_key(password, salt)
            
            # Pad data to multiple of 16 bytes (AES block size)
            padded_data = FileEncryption._pad_data(data)
            
            # Create cipher and encrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Prepend salt and IV to encrypted data
            result = salt + iv + encrypted_data
            
            logger.info(f"Successfully encrypted {len(data)} bytes")
            return result
            
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            return None
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, password: str) -> Optional[bytes]:
        """
        Decrypt data using AES-256-CBC.
        
        Args:
            encrypted_data: Encrypted data with salt and IV prepended
            password: Decryption password
            
        Returns:
            Decrypted data or None if error
        """
        try:
            if len(encrypted_data) < FileEncryption.SALT_LENGTH + FileEncryption.IV_LENGTH:
                logger.error("Encrypted data too short")
                return None
            
            # Extract salt, IV, and encrypted data
            salt = encrypted_data[:FileEncryption.SALT_LENGTH]
            iv = encrypted_data[FileEncryption.SALT_LENGTH:FileEncryption.SALT_LENGTH + FileEncryption.IV_LENGTH]
            ciphertext = encrypted_data[FileEncryption.SALT_LENGTH + FileEncryption.IV_LENGTH:]
            
            # Derive key from password
            key = FileEncryption.derive_key(password, salt)
            
            # Create cipher and decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            data = FileEncryption._unpad_data(padded_data)
            
            logger.info(f"Successfully decrypted {len(data)} bytes")
            return data
            
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            return None
    
    @staticmethod
    def _pad_data(data: bytes) -> bytes:
        """
        Apply PKCS7 padding to data.
        
        Args:
            data: Data to pad
            
        Returns:
            Padded data
        """
        block_size = 16  # AES block size
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _unpad_data(padded_data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data.
        
        Args:
            padded_data: Padded data
            
        Returns:
            Unpadded data
        """
        if not padded_data:
            return padded_data
        
        padding_length = padded_data[-1]
        
        # Validate padding
        if padding_length > 16 or padding_length == 0:
            raise ValueError("Invalid padding")
        
        for i in range(padding_length):
            if padded_data[-(i + 1)] != padding_length:
                raise ValueError("Invalid padding")
        
        return padded_data[:-padding_length]
    
    @staticmethod
    def encrypt_file(file_path: str, password: str) -> Optional[bytes]:
        """
        Encrypt file contents.
        
        Args:
            file_path: Path to file to encrypt
            password: Encryption password
            
        Returns:
            Encrypted file data or None if error
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            return FileEncryption.encrypt_data(data, password)
            
        except Exception as e:
            logger.error(f"Error encrypting file {file_path}: {e}")
            return None
    
    @staticmethod
    def decrypt_to_file(encrypted_data: bytes, password: str, output_path: str) -> bool:
        """
        Decrypt data and save to file.
        
        Args:
            encrypted_data: Encrypted data
            password: Decryption password
            output_path: Output file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            decrypted_data = FileEncryption.decrypt_data(encrypted_data, password)
            if decrypted_data is None:
                return False
            
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"Successfully decrypted and saved file to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error decrypting to file {output_path}: {e}")
            return False
    
    @staticmethod
    def verify_password(encrypted_data: bytes, password: str) -> bool:
        """
        Verify if password can decrypt the data.
        
        Args:
            encrypted_data: Encrypted data to test
            password: Password to verify
            
        Returns:
            True if password is correct, False otherwise
        """
        try:
            result = FileEncryption.decrypt_data(encrypted_data, password)
            return result is not None
        except Exception:
            return False
    
    @staticmethod
    def generate_hash(data: bytes) -> str:
        """
        Generate SHA-256 hash of data for integrity verification.
        
        Args:
            data: Data to hash
            
        Returns:
            Hexadecimal hash string
        """
        try:
            return hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.error(f"Error generating hash: {e}")
            return ""