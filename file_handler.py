"""
File Handler Module
Handles reading and writing different file types for steganography

Author: AI Assistant
"""

import os
import mimetypes
from pathlib import Path
from PIL import Image
import docx
import io


class FileHandler:
    """Handles various file types for steganography operations"""
    
    def __init__(self):
        self.supported_extensions = {
            'text': ['.txt'],
            'document': ['.doc', '.docx'],
            'image': ['.jpg', '.jpeg', '.png', '.bmp', '.gif'],
            'video': ['.mp4', '.avi', '.mov', '.mkv'],
            'audio': ['.mp3', '.wav', '.flac']
        }
    
    def get_file_type(self, file_path):
        """
        Determine file type from extension
        
        Args:
            file_path (str): Path to file
            
        Returns:
            str: File type category
        """
        ext = Path(file_path).suffix.lower()
        
        for file_type, extensions in self.supported_extensions.items():
            if ext in extensions:
                return file_type
        
        return 'unknown'
    
    def read_file(self, file_path):
        """
        Read file and return binary data
        
        Args:
            file_path (str): Path to file
            
        Returns:
            bytes: File data
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_type = self.get_file_type(file_path)
        
        try:
            if file_type == 'text':
                return self._read_text_file(file_path)
            elif file_type == 'document':
                return self._read_document_file(file_path)
            elif file_type == 'image':
                return self._read_image_file(file_path)
            else:
                # For other files, read as binary
                with open(file_path, 'rb') as f:
                    return f.read()
                    
        except Exception as e:
            raise ValueError(f"Error reading file {file_path}: {str(e)}")
    
    def write_file(self, file_path, data):
        """
        Write binary data to file
        
        Args:
            file_path (str): Output file path
            data (bytes): Data to write
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'wb') as f:
                f.write(data)
                
        except Exception as e:
            raise ValueError(f"Error writing file {file_path}: {str(e)}")
    
    def _read_text_file(self, file_path):
        """Read text file with encoding detection"""
        encodings = ['utf-8', 'utf-16', 'ascii', 'latin-1']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    text = f.read()
                return text.encode('utf-8')
            except UnicodeDecodeError:
                continue
        
        # If all encodings fail, read as binary
        with open(file_path, 'rb') as f:
            return f.read()
    
    def _read_document_file(self, file_path):
        """Read document files (.doc, .docx)"""
        ext = Path(file_path).suffix.lower()
        
        if ext == '.docx':
            try:
                doc = docx.Document(file_path)
                text = '\n'.join([paragraph.text for paragraph in doc.paragraphs])
                return text.encode('utf-8')
            except Exception:
                # If docx reading fails, read as binary
                with open(file_path, 'rb') as f:
                    return f.read()
        
        elif ext == '.doc':
            # For .doc files, read as binary (would need python-docx2txt for text extraction)
            with open(file_path, 'rb') as f:
                return f.read()
        
        else:
            with open(file_path, 'rb') as f:
                return f.read()
    
    def _read_image_file(self, file_path):
        """Read image file and return as bytes"""
        try:
            # Try to open with PIL to validate image
            with Image.open(file_path) as img:
                # Convert to bytes
                img_byte_arr = io.BytesIO()
                img_format = img.format or 'PNG'
                img.save(img_byte_arr, format=img_format)
                return img_byte_arr.getvalue()
                
        except Exception:
            # If PIL fails, read as binary
            with open(file_path, 'rb') as f:
                return f.read()
    
    def validate_file(self, file_path, max_size_mb=10):
        """
        Validate file for steganography
        
        Args:
            file_path (str): Path to file
            max_size_mb (int): Maximum file size in MB
            
        Returns:
            tuple: (is_valid, error_message)
        """
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                return False, "File does not exist"
            
            # Check file size
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if file_size_mb > max_size_mb:
                return False, f"File too large: {file_size_mb:.2f} MB (max: {max_size_mb} MB)"
            
            # Check if file is readable
            try:
                self.read_file(file_path)
            except Exception as e:
                return False, f"Cannot read file: {str(e)}"
            
            return True, "File is valid"
            
        except Exception as e:
            return False, f"Error validating file: {str(e)}"
    
    def get_file_info(self, file_path):
        """
        Get detailed file information
        
        Args:
            file_path (str): Path to file
            
        Returns:
            dict: File information
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        stat = os.stat(file_path)
        file_type = self.get_file_type(file_path)
        
        # Get MIME type
        mime_type, _ = mimetypes.guess_type(file_path)
        
        info = {
            'name': os.path.basename(file_path),
            'extension': Path(file_path).suffix.lower(),
            'size': stat.st_size,
            'size_mb': stat.st_size / (1024 * 1024),
            'type': file_type,
            'mime_type': mime_type,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'path': file_path
        }
        
        # Add specific info for images
        if file_type == 'image':
            try:
                with Image.open(file_path) as img:
                    info['image_width'] = img.width
                    info['image_height'] = img.height
                    info['image_mode'] = img.mode
                    info['image_format'] = img.format
            except:
                pass
        
        return info
    
    def compress_data(self, data):
        """
        Compress data using zlib
        
        Args:
            data (bytes): Data to compress
            
        Returns:
            bytes: Compressed data
        """
        import zlib
        return zlib.compress(data)
    
    def decompress_data(self, compressed_data):
        """
        Decompress data using zlib
        
        Args:
            compressed_data (bytes): Compressed data
            
        Returns:
            bytes: Decompressed data
        """
        import zlib
        return zlib.decompress(compressed_data)
    
    def create_file_signature(self, data):
        """
        Create MD5 signature for data integrity
        
        Args:
            data (bytes): Data to sign
            
        Returns:
            str: MD5 hash
        """
        import hashlib
        return hashlib.md5(data).hexdigest()
    
    def verify_file_signature(self, data, signature):
        """
        Verify data integrity using MD5 signature
        
        Args:
            data (bytes): Data to verify
            signature (str): Expected MD5 hash
            
        Returns:
            bool: True if signature matches
        """
        return self.create_file_signature(data) == signature
    
    def split_file_data(self, data, chunk_size=1024):
        """
        Split file data into chunks
        
        Args:
            data (bytes): Data to split
            chunk_size (int): Size of each chunk
            
        Yields:
            bytes: Data chunks
        """
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]
    
    def get_supported_extensions(self):
        """
        Get all supported file extensions
        
        Returns:
            list: List of supported extensions
        """
        extensions = []
        for ext_list in self.supported_extensions.values():
            extensions.extend(ext_list)
        return sorted(extensions)
    
    def is_supported_file(self, file_path):
        """
        Check if file type is supported
        
        Args:
            file_path (str): Path to file
            
        Returns:
            bool: True if file type is supported
        """
        ext = Path(file_path).suffix.lower()
        return ext in self.get_supported_extensions()