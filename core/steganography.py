"""
Video Steganography Core Module
Implements LSB and DCT algorithms for embedding and extracting data in video files.
"""

import cv2
import numpy as np
from scipy.fftpack import dct, idct
import logging
from typing import Tuple, Optional
import os

logger = logging.getLogger(__name__)


class LSBSteganography:
    """Least Significant Bit steganography implementation"""
    
    @staticmethod
    def embed_data(frame: np.ndarray, data: bytes, start_pos: int = 0) -> Tuple[np.ndarray, int]:
        """
        Embed data into a frame using LSB technique
        
        Args:
            frame: Video frame as numpy array
            data: Binary data to embed
            start_pos: Starting position for embedding
            
        Returns:
            Tuple of (modified_frame, end_position)
        """
        try:
            frame_copy = frame.copy()
            flat_frame = frame_copy.flatten()
            
            # Convert data to binary string
            binary_data = ''.join(format(byte, '08b') for byte in data)
            data_len = len(binary_data)
            
            if start_pos + data_len > len(flat_frame):
                raise ValueError("Data too large for frame capacity")
            
            # Embed data in LSBs
            for i, bit in enumerate(binary_data):
                pixel_idx = start_pos + i
                if pixel_idx < len(flat_frame):
                    # Clear LSB and set new bit
                    flat_frame[pixel_idx] = (flat_frame[pixel_idx] & 0xFE) | int(bit)
            
            # Reshape back to original frame shape
            modified_frame = flat_frame.reshape(frame.shape)
            return modified_frame, start_pos + data_len
            
        except Exception as e:
            logger.error(f"LSB embedding failed: {e}")
            raise
    
    @staticmethod
    def extract_data(frame: np.ndarray, data_length: int, start_pos: int = 0) -> bytes:
        """
        Extract data from a frame using LSB technique
        
        Args:
            frame: Video frame as numpy array
            data_length: Length of data to extract in bytes
            start_pos: Starting position for extraction
            
        Returns:
            Extracted binary data
        """
        try:
            flat_frame = frame.flatten()
            binary_data = ""
            
            # Extract LSBs
            for i in range(data_length * 8):
                pixel_idx = start_pos + i
                if pixel_idx < len(flat_frame):
                    binary_data += str(flat_frame[pixel_idx] & 1)
            
            # Convert binary string to bytes
            data = bytearray()
            for i in range(0, len(binary_data), 8):
                if i + 8 <= len(binary_data):
                    byte_val = int(binary_data[i:i+8], 2)
                    data.append(byte_val)
            
            return bytes(data)
            
        except Exception as e:
            logger.error(f"LSB extraction failed: {e}")
            raise


class DCTSteganography:
    """DCT (Discrete Cosine Transform) steganography implementation"""
    
    @staticmethod
    def _apply_dct_2d(block: np.ndarray) -> np.ndarray:
        """Apply 2D DCT to a block"""
        return dct(dct(block.T, norm='ortho').T, norm='ortho')
    
    @staticmethod
    def _apply_idct_2d(block: np.ndarray) -> np.ndarray:
        """Apply 2D inverse DCT to a block"""
        return idct(idct(block.T, norm='ortho').T, norm='ortho')
    
    @staticmethod
    def embed_data(frame: np.ndarray, data: bytes, quality_factor: float = 0.1) -> np.ndarray:
        """
        Embed data into a frame using DCT technique
        
        Args:
            frame: Video frame as numpy array
            data: Binary data to embed
            quality_factor: Controls embedding strength (0.01-1.0)
            
        Returns:
            Modified frame
        """
        try:
            if len(frame.shape) == 3:
                # Convert to grayscale for DCT processing
                gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            else:
                gray_frame = frame.copy()
            
            # Convert data to binary
            binary_data = ''.join(format(byte, '08b') for byte in data)
            
            # Process frame in 8x8 blocks
            height, width = gray_frame.shape
            modified_frame = gray_frame.copy().astype(np.float32)
            
            data_idx = 0
            for i in range(0, height - 7, 8):
                for j in range(0, width - 7, 8):
                    if data_idx >= len(binary_data):
                        break
                    
                    # Extract 8x8 block
                    block = modified_frame[i:i+8, j:j+8]
                    
                    # Apply DCT
                    dct_block = DCTSteganography._apply_dct_2d(block)
                    
                    # Embed bit in mid-frequency coefficient
                    if data_idx < len(binary_data):
                        bit = int(binary_data[data_idx])
                        # Modify coefficient at position (2,2) - mid frequency
                        if bit == 1:
                            dct_block[2, 2] += quality_factor * abs(dct_block[2, 2])
                        else:
                            dct_block[2, 2] -= quality_factor * abs(dct_block[2, 2])
                        data_idx += 1
                    
                    # Apply inverse DCT
                    modified_block = DCTSteganography._apply_idct_2d(dct_block)
                    modified_frame[i:i+8, j:j+8] = modified_block
                
                if data_idx >= len(binary_data):
                    break
            
            # Convert back to original format
            modified_frame = np.clip(modified_frame, 0, 255).astype(np.uint8)
            
            if len(frame.shape) == 3:
                # Convert back to color
                modified_frame = cv2.cvtColor(modified_frame, cv2.COLOR_GRAY2BGR)
            
            return modified_frame
            
        except Exception as e:
            logger.error(f"DCT embedding failed: {e}")
            raise
    
    @staticmethod
    def extract_data(original_frame: np.ndarray, stego_frame: np.ndarray, 
                    data_length: int) -> bytes:
        """
        Extract data from a frame using DCT technique
        
        Args:
            original_frame: Original frame
            stego_frame: Frame with embedded data
            data_length: Length of data to extract in bytes
            
        Returns:
            Extracted binary data
        """
        try:
            if len(original_frame.shape) == 3:
                orig_gray = cv2.cvtColor(original_frame, cv2.COLOR_BGR2GRAY)
                stego_gray = cv2.cvtColor(stego_frame, cv2.COLOR_BGR2GRAY)
            else:
                orig_gray = original_frame.copy()
                stego_gray = stego_frame.copy()
            
            height, width = orig_gray.shape
            binary_data = ""
            
            for i in range(0, height - 7, 8):
                for j in range(0, width - 7, 8):
                    if len(binary_data) >= data_length * 8:
                        break
                    
                    # Extract 8x8 blocks
                    orig_block = orig_gray[i:i+8, j:j+8].astype(np.float32)
                    stego_block = stego_gray[i:i+8, j:j+8].astype(np.float32)
                    
                    # Apply DCT
                    orig_dct = DCTSteganography._apply_dct_2d(orig_block)
                    stego_dct = DCTSteganography._apply_dct_2d(stego_block)
                    
                    # Extract bit from coefficient difference
                    diff = stego_dct[2, 2] - orig_dct[2, 2]
                    binary_data += '1' if diff > 0 else '0'
                
                if len(binary_data) >= data_length * 8:
                    break
            
            # Convert binary string to bytes
            data = bytearray()
            for i in range(0, min(len(binary_data), data_length * 8), 8):
                if i + 8 <= len(binary_data):
                    byte_val = int(binary_data[i:i+8], 2)
                    data.append(byte_val)
            
            return bytes(data)
            
        except Exception as e:
            logger.error(f"DCT extraction failed: {e}")
            raise


class VideoSteganography:
    """Main video steganography class combining LSB and DCT methods"""
    
    def __init__(self, method: str = "LSB"):
        """
        Initialize with specified method
        
        Args:
            method: "LSB" or "DCT"
        """
        self.method = method.upper()
        if self.method not in ["LSB", "DCT"]:
            raise ValueError("Method must be 'LSB' or 'DCT'")
        
        logger.info(f"VideoSteganography initialized with {self.method} method")
    
    def calculate_capacity(self, video_path: str) -> int:
        """
        Calculate maximum data capacity for a video file
        
        Args:
            video_path: Path to video file
            
        Returns:
            Maximum capacity in bytes
        """
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise ValueError("Cannot open video file")
            
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            
            cap.release()
            
            if self.method == "LSB":
                # LSB can use 1 bit per pixel per frame
                pixels_per_frame = width * height * 3  # RGB channels
                total_bits = frame_count * pixels_per_frame
                capacity = total_bits // 8  # Convert to bytes
            else:  # DCT
                # DCT uses 8x8 blocks, 1 bit per block per frame
                blocks_per_frame = (width // 8) * (height // 8)
                total_bits = frame_count * blocks_per_frame
                capacity = total_bits // 8  # Convert to bytes
            
            # Reserve space for metadata (file size, type, etc.)
            metadata_overhead = 1024  # 1KB for metadata
            capacity = max(0, capacity - metadata_overhead)
            
            logger.info(f"Video capacity calculated: {capacity} bytes using {self.method}")
            return capacity
            
        except Exception as e:
            logger.error(f"Capacity calculation failed: {e}")
            raise
    
    def embed_file(self, cover_video_path: str, secret_file_path: str, 
                   output_path: str, progress_callback=None) -> bool:
        """
        Embed a secret file into a cover video
        
        Args:
            cover_video_path: Path to cover video
            secret_file_path: Path to secret file
            output_path: Path for output video
            progress_callback: Optional callback for progress updates
            
        Returns:
            True if successful
        """
        try:
            # Read secret file
            with open(secret_file_path, 'rb') as f:
                secret_data = f.read()
            
            # Check capacity
            capacity = self.calculate_capacity(cover_video_path)
            if len(secret_data) > capacity:
                raise ValueError(f"Secret file too large. Max capacity: {capacity} bytes")
            
            # Prepare metadata
            file_ext = os.path.splitext(secret_file_path)[1]
            metadata = {
                'size': len(secret_data),
                'extension': file_ext
            }
            
            # Open video
            cap = cv2.VideoCapture(cover_video_path)
            if not cap.isOpened():
                raise ValueError("Cannot open cover video")
            
            # Get video properties
            fps = cap.get(cv2.CAP_PROP_FPS)
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            # Setup video writer
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
            
            # Embed data
            data_embedded = 0
            frames_processed = 0
            
            # Create header with metadata
            header = f"{metadata['size']}|{metadata['extension']}|".encode()
            full_data = header + secret_data
            
            if self.method == "LSB":
                data_pos = 0
                while True:
                    ret, frame = cap.read()
                    if not ret:
                        break
                    
                    if data_pos < len(full_data):
                        # Calculate how much data to embed in this frame
                        frame_capacity = frame.size // 8  # bits to bytes
                        remaining_data = len(full_data) - data_pos
                        chunk_size = min(frame_capacity, remaining_data)
                        
                        if chunk_size > 0:
                            data_chunk = full_data[data_pos:data_pos + chunk_size]
                            frame, _ = LSBSteganography.embed_data(frame, data_chunk)
                            data_pos += chunk_size
                    
                    out.write(frame)
                    frames_processed += 1
                    
                    if progress_callback:
                        progress = (frames_processed / frame_count) * 100
                        progress_callback(progress)
            
            else:  # DCT method
                # For DCT, we'll embed data across frames
                data_per_frame = len(full_data) // frame_count + 1
                data_pos = 0
                
                while True:
                    ret, frame = cap.read()
                    if not ret:
                        break
                    
                    if data_pos < len(full_data):
                        chunk_size = min(data_per_frame, len(full_data) - data_pos)
                        if chunk_size > 0:
                            data_chunk = full_data[data_pos:data_pos + chunk_size]
                            frame = DCTSteganography.embed_data(frame, data_chunk)
                            data_pos += chunk_size
                    
                    out.write(frame)
                    frames_processed += 1
                    
                    if progress_callback:
                        progress = (frames_processed / frame_count) * 100
                        progress_callback(progress)
            
            cap.release()
            out.release()
            
            logger.info(f"Successfully embedded {len(secret_data)} bytes using {self.method}")
            return True
            
        except Exception as e:
            logger.error(f"Embedding failed: {e}")
            raise
    
    def extract_file(self, stego_video_path: str, output_file_path: str, 
                    original_video_path: str = None, progress_callback=None) -> bool:
        """
        Extract a secret file from a stego video
        
        Args:
            stego_video_path: Path to stego video
            output_file_path: Path for extracted file
            original_video_path: Original video (required for DCT)
            progress_callback: Optional callback for progress updates
            
        Returns:
            True if successful
        """
        try:
            cap = cv2.VideoCapture(stego_video_path)
            if not cap.isOpened():
                raise ValueError("Cannot open stego video")
            
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            if self.method == "LSB":
                # Extract header first to get metadata
                ret, first_frame = cap.read()
                if not ret:
                    raise ValueError("Cannot read first frame")
                
                # Extract header (assume max 100 bytes for header)
                header_data = LSBSteganography.extract_data(first_frame, 100, 0)
                header_str = header_data.decode('utf-8', errors='ignore')
                
                # Parse header
                parts = header_str.split('|')
                if len(parts) < 2:
                    raise ValueError("Invalid header format")
                
                file_size = int(parts[0])
                file_ext = parts[1]
                header_size = len(f"{file_size}|{file_ext}|".encode())
                
                # Extract actual data
                cap.set(cv2.CAP_PROP_POS_FRAMES, 0)  # Reset to beginning
                extracted_data = b""
                data_pos = header_size
                remaining_size = file_size
                
                frame_idx = 0
                while remaining_size > 0:
                    ret, frame = cap.read()
                    if not ret:
                        break
                    
                    frame_capacity = frame.size // 8
                    if frame_idx == 0:
                        # Skip header in first frame
                        available_capacity = frame_capacity - header_size
                        start_pos = header_size
                    else:
                        available_capacity = frame_capacity
                        start_pos = 0
                    
                    chunk_size = min(available_capacity, remaining_size)
                    if chunk_size > 0:
                        chunk_data = LSBSteganography.extract_data(frame, chunk_size, start_pos)
                        extracted_data += chunk_data
                        remaining_size -= chunk_size
                    
                    frame_idx += 1
                    if progress_callback:
                        progress = ((file_size - remaining_size) / file_size) * 100
                        progress_callback(progress)
            
            else:  # DCT method
                if not original_video_path:
                    raise ValueError("Original video required for DCT extraction")
                
                orig_cap = cv2.VideoCapture(original_video_path)
                if not orig_cap.isOpened():
                    raise ValueError("Cannot open original video")
                
                # For DCT, we need to process frame by frame
                # This is a simplified extraction - in practice, you'd need
                # to store metadata about data distribution
                extracted_data = b""
                frame_idx = 0
                
                while True:
                    ret1, stego_frame = cap.read()
                    ret2, orig_frame = orig_cap.read()
                    
                    if not ret1 or not ret2:
                        break
                    
                    # Extract data from frame difference
                    frame_data = DCTSteganography.extract_data(orig_frame, stego_frame, 100)
                    extracted_data += frame_data
                    
                    frame_idx += 1
                    if progress_callback:
                        progress = (frame_idx / frame_count) * 100
                        progress_callback(progress)
                
                orig_cap.release()
            
            cap.release()
            
            # Write extracted file
            with open(output_file_path, 'wb') as f:
                f.write(extracted_data)
            
            logger.info(f"Successfully extracted {len(extracted_data)} bytes using {self.method}")
            return True
            
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise