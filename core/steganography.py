"""
Core steganography algorithms for video embedding and extraction.
"""

import cv2
import numpy as np
import json
import struct
from typing import Optional, Tuple, Dict, Any, Callable
from scipy.fft import dct, idct

from core.video_processor import VideoProcessor
from core.encryption import FileEncryption
from utils.file_handler import FileHandler
from utils.logger import get_logger

logger = get_logger(__name__)


class VideoSteganography:
    """Main class for video steganography operations."""
    
    def __init__(self):
        self.video_processor = VideoProcessor()
        self.file_handler = FileHandler()
    
    def embed_file(self, cover_video_path: str, secret_file_path: str, 
                   output_path: str, algorithm: str = "LSB", 
                   password: Optional[str] = None,
                   progress_callback: Optional[Callable[[int], None]] = None) -> Tuple[bool, str]:
        """
        Embed secret file into cover video.
        
        Args:
            cover_video_path: Path to cover video
            secret_file_path: Path to secret file
            output_path: Path for output video
            algorithm: Steganography algorithm ("LSB" or "DCT")
            password: Optional encryption password
            progress_callback: Optional progress callback function
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            logger.info(f"Starting embedding process: {algorithm} algorithm")
            
            # Validate inputs
            is_valid, error = self._validate_embedding_inputs(
                cover_video_path, secret_file_path, algorithm
            )
            if not is_valid:
                return False, error
            
            # Load secret file data
            secret_data = FileHandler.read_file_bytes(secret_file_path)
            if secret_data is None:
                return False, "Could not read secret file"
            
            # Encrypt if password provided
            if password:
                logger.info("Encrypting secret data")
                secret_data = FileEncryption.encrypt_data(secret_data, password)
                if secret_data is None:
                    return False, "Failed to encrypt secret data"
            
            # Create metadata
            metadata = self._create_metadata(secret_file_path, len(secret_data), bool(password))
            
            # Combine metadata and data
            payload = self._create_payload(metadata, secret_data)
            
            # Check capacity
            max_capacity = self.video_processor.calculate_max_capacity(cover_video_path, algorithm)
            if len(payload) > max_capacity:
                return False, f"Secret file too large. Max capacity: {max_capacity} bytes, " \
                             f"required: {len(payload)} bytes"
            
            # Load video frames
            frames = self.video_processor.load_video_frames(cover_video_path)
            if frames is None:
                return False, "Could not load video frames"
            
            # Embed data using selected algorithm
            if algorithm.upper() == "LSB":
                modified_frames = self._embed_lsb(frames, payload, progress_callback)
            elif algorithm.upper() == "DCT":
                modified_frames = self._embed_dct(frames, payload, progress_callback)
            else:
                return False, f"Unknown algorithm: {algorithm}"
            
            if modified_frames is None:
                return False, "Failed to embed data"
            
            # Save output video
            video_props = self.video_processor.get_video_properties(cover_video_path)
            if not video_props:
                return False, "Could not get video properties"
            
            success = self.video_processor.save_video_frames(
                modified_frames, output_path, video_props['fps']
            )
            
            if success:
                logger.info(f"Successfully embedded {len(secret_data)} bytes using {algorithm}")
                return True, "File embedded successfully"
            else:
                return False, "Failed to save output video"
                
        except Exception as e:
            logger.error(f"Error during embedding: {e}")
            return False, f"Embedding failed: {str(e)}"
    
    def extract_file(self, stego_video_path: str, output_path: str,
                     algorithm: str = "LSB", password: Optional[str] = None,
                     progress_callback: Optional[Callable[[int], None]] = None) -> Tuple[bool, str]:
        """
        Extract secret file from stego video.
        
        Args:
            stego_video_path: Path to stego video
            output_path: Path for extracted file
            algorithm: Steganography algorithm used
            password: Optional decryption password
            progress_callback: Optional progress callback function
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            logger.info(f"Starting extraction process: {algorithm} algorithm")
            
            # Validate inputs
            is_valid, error = FileHandler.validate_cover_video(stego_video_path)
            if not is_valid:
                return False, error
            
            # Load video frames
            frames = self.video_processor.load_video_frames(stego_video_path)
            if frames is None:
                return False, "Could not load video frames"
            
            # Extract data using selected algorithm
            if algorithm.upper() == "LSB":
                payload = self._extract_lsb(frames, progress_callback)
            elif algorithm.upper() == "DCT":
                payload = self._extract_dct(frames, progress_callback)
            else:
                return False, f"Unknown algorithm: {algorithm}"
            
            if payload is None:
                return False, "Failed to extract data"
            
            # Parse payload
            metadata, secret_data = self._parse_payload(payload)
            if metadata is None or secret_data is None:
                return False, "Failed to parse extracted data"
            
            # Decrypt if needed
            if metadata.get('encrypted', False):
                if not password:
                    return False, "Password required for encrypted file"
                
                logger.info("Decrypting extracted data")
                secret_data = FileEncryption.decrypt_data(secret_data, password)
                if secret_data is None:
                    return False, "Failed to decrypt data (wrong password?)"
            
            # Determine output filename
            if output_path.endswith('/') or output_path.endswith('\\'):
                # Directory provided, use original filename
                original_name = metadata.get('filename', 'extracted_file')
                output_path = output_path + original_name
            
            # Save extracted file
            success = FileHandler.write_file_bytes(output_path, secret_data)
            if success:
                logger.info(f"Successfully extracted {len(secret_data)} bytes")
                return True, f"File extracted to {output_path}"
            else:
                return False, "Failed to save extracted file"
                
        except Exception as e:
            logger.error(f"Error during extraction: {e}")
            return False, f"Extraction failed: {str(e)}"
    
    def _validate_embedding_inputs(self, cover_path: str, secret_path: str, 
                                 algorithm: str) -> Tuple[bool, str]:
        """Validate inputs for embedding operation."""
        # Validate cover video
        is_valid, error = FileHandler.validate_cover_video(cover_path)
        if not is_valid:
            return False, f"Cover video error: {error}"
        
        # Validate secret file
        is_valid, error = FileHandler.validate_secret_file(secret_path)
        if not is_valid:
            return False, f"Secret file error: {error}"
        
        # Validate algorithm
        if algorithm.upper() not in ["LSB", "DCT"]:
            return False, "Algorithm must be 'LSB' or 'DCT'"
        
        # Check video compatibility
        is_valid, error = self.video_processor.validate_video_compatibility(cover_path)
        if not is_valid:
            return False, f"Video compatibility error: {error}"
        
        return True, ""
    
    def _create_metadata(self, file_path: str, data_size: int, encrypted: bool) -> Dict[str, Any]:
        """Create metadata for embedded file."""
        import os
        return {
            'filename': os.path.basename(file_path),
            'extension': FileHandler.get_file_extension(file_path),
            'size': data_size,
            'encrypted': encrypted,
            'version': '1.0'
        }
    
    def _create_payload(self, metadata: Dict[str, Any], data: bytes) -> bytes:
        """Create payload with metadata and data."""
        # Serialize metadata to JSON
        metadata_json = json.dumps(metadata).encode('utf-8')
        metadata_size = len(metadata_json)
        
        # Create payload: [metadata_size(4 bytes)][metadata][data]
        payload = struct.pack('<I', metadata_size) + metadata_json + data
        
        return payload
    
    def _parse_payload(self, payload: bytes) -> Tuple[Optional[Dict[str, Any]], Optional[bytes]]:
        """Parse payload to extract metadata and data."""
        try:
            if len(payload) < 4:
                return None, None
            
            # Extract metadata size
            metadata_size = struct.unpack('<I', payload[:4])[0]
            
            if len(payload) < 4 + metadata_size:
                return None, None
            
            # Extract metadata
            metadata_json = payload[4:4 + metadata_size]
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Extract data
            data = payload[4 + metadata_size:]
            
            return metadata, data
            
        except Exception as e:
            logger.error(f"Error parsing payload: {e}")
            return None, None
    
    def _embed_lsb(self, frames: np.ndarray, payload: bytes,
                   progress_callback: Optional[Callable[[int], None]] = None) -> Optional[np.ndarray]:
        """Embed data using LSB algorithm."""
        try:
            logger.info("Starting LSB embedding")
            
            # Convert payload to bits
            payload_bits = self._bytes_to_bits(payload)
            total_bits = len(payload_bits)
            
            if total_bits == 0:
                return frames
            
            modified_frames = frames.copy()
            bit_index = 0
            total_pixels = frames.shape[0] * frames.shape[1] * frames.shape[2]
            
            for frame_idx, frame in enumerate(modified_frames):
                if bit_index >= total_bits:
                    break
                
                height, width, channels = frame.shape
                
                for y in range(height):
                    for x in range(width):
                        for c in range(channels):
                            if bit_index >= total_bits:
                                break
                            
                            # Modify LSB
                            pixel_value = frame[y, x, c]
                            new_value = (pixel_value & 0xFE) | payload_bits[bit_index]
                            modified_frames[frame_idx, y, x, c] = new_value
                            
                            bit_index += 1
                
                # Update progress
                if progress_callback and frame_idx % 10 == 0:
                    progress = int((frame_idx / len(frames)) * 100)
                    progress_callback(progress)
            
            logger.info(f"Embedded {total_bits} bits using LSB")
            return modified_frames
            
        except Exception as e:
            logger.error(f"Error in LSB embedding: {e}")
            return None
    
    def _extract_lsb(self, frames: np.ndarray,
                     progress_callback: Optional[Callable[[int], None]] = None) -> Optional[bytes]:
        """Extract data using LSB algorithm."""
        try:
            logger.info("Starting LSB extraction")
            
            # First, extract metadata size (4 bytes = 32 bits)
            bits = []
            bit_count = 0
            metadata_size_bits = 32
            
            for frame_idx, frame in enumerate(frames):
                if bit_count >= metadata_size_bits:
                    break
                
                height, width, channels = frame.shape
                
                for y in range(height):
                    for x in range(width):
                        for c in range(channels):
                            if bit_count >= metadata_size_bits:
                                break
                            
                            # Extract LSB
                            pixel_value = frame[y, x, c]
                            bits.append(pixel_value & 1)
                            bit_count += 1
            
            # Convert bits to metadata size
            metadata_size = self._bits_to_int(bits[:32])
            total_payload_bits = (4 + metadata_size) * 8  # Start with metadata + size
            
            # Continue extracting until we have metadata
            while bit_count < total_payload_bits and frame_idx < len(frames):
                frame = frames[frame_idx]
                height, width, channels = frame.shape
                
                for y in range(height):
                    for x in range(width):
                        for c in range(channels):
                            if bit_count >= total_payload_bits:
                                break
                            
                            pixel_value = frame[y, x, c]
                            bits.append(pixel_value & 1)
                            bit_count += 1
                
                frame_idx += 1
            
            # Parse metadata to get actual data size
            partial_payload = self._bits_to_bytes(bits[:total_payload_bits])
            metadata, _ = self._parse_payload(partial_payload)
            
            if metadata is None:
                logger.error("Could not parse metadata")
                return None
            
            # Calculate total size needed
            actual_data_size = metadata.get('size', 0)
            total_size = 4 + len(json.dumps(metadata).encode('utf-8')) + actual_data_size
            total_bits_needed = total_size * 8
            
            # Extract remaining bits if needed
            while bit_count < total_bits_needed and frame_idx < len(frames):
                frame = frames[frame_idx]
                height, width, channels = frame.shape
                
                for y in range(height):
                    for x in range(width):
                        for c in range(channels):
                            if bit_count >= total_bits_needed:
                                break
                            
                            pixel_value = frame[y, x, c]
                            bits.append(pixel_value & 1)
                            bit_count += 1
                
                frame_idx += 1
                
                # Update progress
                if progress_callback and frame_idx % 10 == 0:
                    progress = int((frame_idx / len(frames)) * 100)
                    progress_callback(progress)
            
            # Convert bits to bytes
            payload = self._bits_to_bytes(bits[:total_bits_needed])
            
            logger.info(f"Extracted {len(payload)} bytes using LSB")
            return payload
            
        except Exception as e:
            logger.error(f"Error in LSB extraction: {e}")
            return None
    
    def _embed_dct(self, frames: np.ndarray, payload: bytes,
                   progress_callback: Optional[Callable[[int], None]] = None) -> Optional[np.ndarray]:
        """Embed data using DCT algorithm."""
        try:
            logger.info("Starting DCT embedding")
            
            payload_bits = self._bytes_to_bits(payload)
            total_bits = len(payload_bits)
            
            if total_bits == 0:
                return frames
            
            modified_frames = frames.copy().astype(np.float32)
            bit_index = 0
            
            for frame_idx, frame in enumerate(modified_frames):
                if bit_index >= total_bits:
                    break
                
                # Convert to YUV for better embedding
                yuv_frame = cv2.cvtColor(frame.astype(np.uint8), cv2.COLOR_BGR2YUV)
                y_channel = yuv_frame[:, :, 0].astype(np.float32)
                
                height, width = y_channel.shape
                
                # Process 8x8 blocks
                for i in range(0, height - 8, 8):
                    for j in range(0, width - 8, 8):
                        if bit_index >= total_bits:
                            break
                        
                        # Extract 8x8 block
                        block = y_channel[i:i+8, j:j+8]
                        
                        # Apply DCT
                        dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                        
                        # Embed bit in mid-frequency coefficient
                        if payload_bits[bit_index] == 1:
                            dct_block[2, 3] = abs(dct_block[2, 3]) + 10
                        else:
                            dct_block[2, 3] = abs(dct_block[2, 3]) - 10
                        
                        # Apply inverse DCT
                        reconstructed_block = idct(idct(dct_block.T, norm='ortho').T, norm='ortho')
                        
                        # Clip values to valid range
                        reconstructed_block = np.clip(reconstructed_block, 0, 255)
                        
                        # Update frame
                        y_channel[i:i+8, j:j+8] = reconstructed_block
                        bit_index += 1
                
                # Convert back to BGR
                yuv_frame[:, :, 0] = y_channel.astype(np.uint8)
                modified_frames[frame_idx] = cv2.cvtColor(yuv_frame, cv2.COLOR_YUV2BGR).astype(np.float32)
                
                # Update progress
                if progress_callback and frame_idx % 10 == 0:
                    progress = int((frame_idx / len(frames)) * 100)
                    progress_callback(progress)
            
            logger.info(f"Embedded {total_bits} bits using DCT")
            return modified_frames.astype(np.uint8)
            
        except Exception as e:
            logger.error(f"Error in DCT embedding: {e}")
            return None
    
    def _extract_dct(self, frames: np.ndarray,
                     progress_callback: Optional[Callable[[int], None]] = None) -> Optional[bytes]:
        """Extract data using DCT algorithm."""
        try:
            logger.info("Starting DCT extraction")
            
            bits = []
            
            # First pass: extract metadata size
            metadata_size_bits = 32
            bit_count = 0
            
            for frame_idx, frame in enumerate(frames):
                if bit_count >= metadata_size_bits:
                    break
                
                # Convert to YUV
                yuv_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2YUV)
                y_channel = yuv_frame[:, :, 0].astype(np.float32)
                
                height, width = y_channel.shape
                
                # Process 8x8 blocks
                for i in range(0, height - 8, 8):
                    for j in range(0, width - 8, 8):
                        if bit_count >= metadata_size_bits:
                            break
                        
                        # Extract 8x8 block
                        block = y_channel[i:i+8, j:j+8]
                        
                        # Apply DCT
                        dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                        
                        # Extract bit from coefficient
                        coeff_value = dct_block[2, 3]
                        bit = 1 if coeff_value > 0 else 0
                        bits.append(bit)
                        bit_count += 1
            
            # Get metadata size and continue extraction
            metadata_size = self._bits_to_int(bits[:32])
            total_payload_bits = (4 + metadata_size) * 8
            
            # Continue extraction for full payload
            frame_idx = 0
            while bit_count < total_payload_bits and frame_idx < len(frames):
                frame = frames[frame_idx]
                yuv_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2YUV)
                y_channel = yuv_frame[:, :, 0].astype(np.float32)
                
                height, width = y_channel.shape
                
                for i in range(0, height - 8, 8):
                    for j in range(0, width - 8, 8):
                        if bit_count >= total_payload_bits:
                            break
                        
                        if bit_count < len(bits):
                            bit_count += 1
                            continue
                        
                        block = y_channel[i:i+8, j:j+8]
                        dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                        
                        coeff_value = dct_block[2, 3]
                        bit = 1 if coeff_value > 0 else 0
                        bits.append(bit)
                        bit_count += 1
                
                frame_idx += 1
                
                if progress_callback and frame_idx % 10 == 0:
                    progress = int((frame_idx / len(frames)) * 100)
                    progress_callback(progress)
            
            # Parse metadata to get actual size
            partial_payload = self._bits_to_bytes(bits[:total_payload_bits])
            metadata, _ = self._parse_payload(partial_payload)
            
            if metadata is None:
                return None
            
            # Extract remaining data
            actual_data_size = metadata.get('size', 0)
            total_size = 4 + len(json.dumps(metadata).encode('utf-8')) + actual_data_size
            total_bits_needed = total_size * 8
            
            while bit_count < total_bits_needed and frame_idx < len(frames):
                frame = frames[frame_idx]
                yuv_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2YUV)
                y_channel = yuv_frame[:, :, 0].astype(np.float32)
                
                height, width = y_channel.shape
                
                for i in range(0, height - 8, 8):
                    for j in range(0, width - 8, 8):
                        if bit_count >= total_bits_needed:
                            break
                        
                        if bit_count < len(bits):
                            bit_count += 1
                            continue
                        
                        block = y_channel[i:i+8, j:j+8]
                        dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                        
                        coeff_value = dct_block[2, 3]
                        bit = 1 if coeff_value > 0 else 0
                        bits.append(bit)
                        bit_count += 1
                
                frame_idx += 1
            
            payload = self._bits_to_bytes(bits[:total_bits_needed])
            
            logger.info(f"Extracted {len(payload)} bytes using DCT")
            return payload
            
        except Exception as e:
            logger.error(f"Error in DCT extraction: {e}")
            return None
    
    def _bytes_to_bits(self, data: bytes) -> list:
        """Convert bytes to list of bits."""
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
        return bits
    
    def _bits_to_bytes(self, bits: list) -> bytes:
        """Convert list of bits to bytes."""
        # Pad bits to multiple of 8
        while len(bits) % 8 != 0:
            bits.append(0)
        
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte |= bits[i + j] << (7 - j)
            bytes_data.append(byte)
        
        return bytes(bytes_data)
    
    def _bits_to_int(self, bits: list) -> int:
        """Convert list of bits to integer."""
        result = 0
        for bit in bits:
            result = (result << 1) | bit
        return result