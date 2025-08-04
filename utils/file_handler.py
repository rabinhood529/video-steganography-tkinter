"""
File handling utilities for video steganography application.
"""

import os
import mimetypes
from typing import Tuple, Optional
from docx import Document
from utils.logger import get_logger

logger = get_logger(__name__)


class FileHandler:
    """Handles file operations and validation."""
    
    # Supported file types
    SUPPORTED_SECRET_TYPES = {
        '.txt': 'text/plain',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.mp4': 'video/mp4',
        '.avi': 'video/x-msvideo'
    }
    
    SUPPORTED_VIDEO_TYPES = {
        '.mp4': 'video/mp4',
        '.avi': 'video/x-msvideo'
    }
    
    MAX_VIDEO_SIZE = 50 * 1024 * 1024  # 50MB in bytes
    
    @staticmethod
    def validate_file_exists(filepath: str) -> bool:
        """Check if file exists and is readable."""
        try:
            return os.path.isfile(filepath) and os.access(filepath, os.R_OK)
        except Exception as e:
            logger.error(f"Error checking file existence: {e}")
            return False
    
    @staticmethod
    def get_file_size(filepath: str) -> int:
        """Get file size in bytes."""
        try:
            return os.path.getsize(filepath)
        except Exception as e:
            logger.error(f"Error getting file size: {e}")
            return 0
    
    @staticmethod
    def get_file_extension(filepath: str) -> str:
        """Get file extension in lowercase."""
        return os.path.splitext(filepath)[1].lower()
    
    @staticmethod
    def validate_secret_file(filepath: str) -> Tuple[bool, str]:
        """
        Validate secret file type and accessibility.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not FileHandler.validate_file_exists(filepath):
            return False, "File does not exist or is not readable"
        
        ext = FileHandler.get_file_extension(filepath)
        if ext not in FileHandler.SUPPORTED_SECRET_TYPES:
            supported = ', '.join(FileHandler.SUPPORTED_SECRET_TYPES.keys())
            return False, f"Unsupported file type. Supported: {supported}"
        
        return True, ""
    
    @staticmethod
    def validate_cover_video(filepath: str) -> Tuple[bool, str]:
        """
        Validate cover video file.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not FileHandler.validate_file_exists(filepath):
            return False, "Video file does not exist or is not readable"
        
        ext = FileHandler.get_file_extension(filepath)
        if ext not in FileHandler.SUPPORTED_VIDEO_TYPES:
            supported = ', '.join(FileHandler.SUPPORTED_VIDEO_TYPES.keys())
            return False, f"Unsupported video format. Supported: {supported}"
        
        file_size = FileHandler.get_file_size(filepath)
        if file_size > FileHandler.MAX_VIDEO_SIZE:
            size_mb = file_size / (1024 * 1024)
            return False, f"Video file too large: {size_mb:.1f}MB (max 50MB)"
        
        return True, ""
    
    @staticmethod
    def read_file_bytes(filepath: str) -> Optional[bytes]:
        """Read file as bytes."""
        try:
            with open(filepath, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {e}")
            return None
    
    @staticmethod
    def write_file_bytes(filepath: str, data: bytes) -> bool:
        """Write bytes to file."""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'wb') as f:
                f.write(data)
            return True
        except Exception as e:
            logger.error(f"Error writing file {filepath}: {e}")
            return False
    
    @staticmethod
    def read_text_file(filepath: str) -> Optional[str]:
        """Read text file content."""
        try:
            ext = FileHandler.get_file_extension(filepath)
            
            if ext == '.txt':
                with open(filepath, 'r', encoding='utf-8') as f:
                    return f.read()
            elif ext in ['.doc', '.docx']:
                doc = Document(filepath)
                return '\n'.join([paragraph.text for paragraph in doc.paragraphs])
            else:
                return None
        except Exception as e:
            logger.error(f"Error reading text file {filepath}: {e}")
            return None
    
    @staticmethod
    def get_safe_filename(filepath: str) -> str:
        """Generate safe filename for output."""
        base, ext = os.path.splitext(filepath)
        counter = 1
        new_path = f"{base}_stego{ext}"
        
        while os.path.exists(new_path):
            new_path = f"{base}_stego_{counter}{ext}"
            counter += 1
        
        return new_path
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format file size in human-readable format."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"