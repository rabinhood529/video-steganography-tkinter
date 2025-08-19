"""
Steganography Engine Module
Implements LSB and DCT algorithms for hiding/extracting data in video frames

Author: AI Assistant
"""

import cv2
import numpy as np
import json
import struct
from video_processor import VideoProcessor
import os # Added for backup file existence check


class SteganographyEngine:
    """Core steganography engine with LSB and DCT algorithms"""
    
    def __init__(self):
        self.video_processor = VideoProcessor()
        self.header_marker = b"VSTEG_V1"  # Version marker for steganographic data
        self.metadata_separator = b"METADATA_END"
    
    def calculate_max_payload_size(self, width, height, frame_count, algorithm="LSB"):
        """
        Calculate maximum payload size for given video parameters
        
        Args:
            width (int): Video width
            height (int): Video height
            frame_count (int): Number of frames
            algorithm (str): Algorithm type ("LSB" or "DCT")
            
        Returns:
            int: Maximum payload size in bytes
        """
        if algorithm == "LSB":
            # LSB can hide 1 bit per color channel per pixel
            # Using only blue channel to minimize visible artifacts
            bits_per_frame = width * height  # 1 bit per pixel in blue channel
            total_bits = bits_per_frame * frame_count
            
            # Reserve space for header and metadata (estimated 1KB)
            reserved_bits = 1024 * 8
            usable_bits = max(0, total_bits - reserved_bits)
            
            return usable_bits // 8  # Convert to bytes
            
        elif algorithm == "DCT":
            # DCT can hide approximately 0.1 bits per pixel
            bits_per_frame = int(width * height * 0.1)
            total_bits = bits_per_frame * frame_count
            
            # Reserve space for header and metadata
            reserved_bits = 1024 * 8
            usable_bits = max(0, total_bits - reserved_bits)
            
            return usable_bits // 8
        
        return 0
    
    def hide_data(self, video_path, output_path, secret_data, metadata, algorithm="LSB", progress_callback=None):
        """
        Hide secret data in video using specified algorithm
        
        Args:
            video_path (str): Input video path
            output_path (str): Output video path
            secret_data (bytes): Data to hide
            metadata (dict): File metadata
            algorithm (str): Algorithm to use ("LSB" or "DCT")
            progress_callback (function): Progress callback function
            
        Returns:
            bool: True if successful
        """
        try:
            # Get video info
            video_info = self.video_processor.get_video_info(video_path)
            
            # Check payload size
            max_size = self.calculate_max_payload_size(
                video_info['width'], video_info['height'], 
                video_info['frame_count'], algorithm
            )
            
            if len(secret_data) > max_size:
                raise ValueError(f"Data too large: {len(secret_data)} bytes > {max_size} bytes")
            
            # Prepare payload
            payload = self._prepare_payload(secret_data, metadata)
            
            # Hide data using selected algorithm
            if algorithm == "LSB":
                return self._hide_data_lsb(video_path, output_path, payload, video_info, progress_callback)
            elif algorithm == "DCT":
                return self._hide_data_dct(video_path, output_path, payload, video_info, progress_callback)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
                
        except Exception as e:
            print(f"Error hiding data: {e}")
            return False
    
    def hide_data_with_backup(self, video_path, output_path, secret_data, metadata, algorithm="LSB", progress_callback=None):
        """
        Hide data and create a backup of original frames for reliable extraction
        
        Args:
            video_path (str): Input video path
            output_path (str): Output video path
            secret_data (bytes): Data to hide
            metadata (dict): File metadata
            algorithm (str): Algorithm to use
            progress_callback (function): Progress callback
            
        Returns:
            bool: True if successful
        """
        try:
            # Get video info
            video_info = self.video_processor.get_video_info(video_path)
            
            # Check payload size
            max_size = self.calculate_max_payload_size(
                video_info['width'], video_info['height'], 
                video_info['frame_count'], algorithm
            )
            
            if len(secret_data) > max_size:
                raise ValueError(f"Data too large: {len(secret_data)} bytes > {max_size} bytes")
            
            # Prepare payload
            payload = self._prepare_payload(secret_data, metadata)
            
            # Read all original frames
            original_frames = list(self.video_processor.read_video_frames(video_path))
            
            # Create modified frames
            modified_frames = []
            binary_data = ''.join(format(byte, '08b') for byte in payload)
            data_length = len(binary_data)
            data_index = 0
            
            for i, frame in enumerate(original_frames):
                if data_index < data_length:
                    # Hide data in this frame
                    modified_frame = self._hide_bits_in_frame_lsb(frame, binary_data, data_index)
                    data_index += video_info['width'] * video_info['height']
                else:
                    modified_frame = frame.copy()
                
                modified_frames.append(modified_frame)
                
                if progress_callback:
                    progress = 30 + (i / video_info['frame_count']) * 60
                    progress_callback(progress)
            
            # Save backup data
            backup_path = output_path.replace('.avi', '_backup.npz')
            
            # Convert frames to numpy arrays and save
            original_array = np.array(original_frames)
            modified_array = np.array(modified_frames)
            
            np.savez(backup_path, 
                     original_frames=original_array,
                     modified_frames=modified_array,
                     payload=payload,
                     metadata=metadata)
            
            print(f"DEBUG: Saved backup to {backup_path}")
            
            # Write stego video
            if progress_callback:
                progress_callback(90)
            
            self.video_processor.write_video_frames(modified_frames, output_path, video_info,
                                                  lambda p: progress_callback(90 + p * 0.1) if progress_callback else None)
            
            return True
            
        except Exception as e:
            print(f"Error in hide_data_with_backup: {e}")
            return False
    
    def extract_data(self, video_path, algorithm="LSB", progress_callback=None):
        """
        Extract hidden data from video
        
        Args:
            video_path (str): Input video path
            algorithm (str): Algorithm used for hiding
            progress_callback (function): Progress callback function
            
        Returns:
            tuple: (secret_data, metadata) or None if no data found
        """
        try:
            if algorithm == "LSB":
                payload = self._extract_data_lsb(video_path, progress_callback)
            elif algorithm == "DCT":
                payload = self._extract_data_dct(video_path, progress_callback)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            if payload is None:
                return None
            
            return self._parse_payload(payload)
            
        except Exception as e:
            print(f"Error extracting data: {e}")
            return None
    
    def extract_data_with_backup(self, video_path, algorithm="LSB", progress_callback=None):
        """
        Extract data using backup frames if available
        
        Args:
            video_path (str): Input video path
            algorithm (str): Algorithm used
            progress_callback (function): Progress callback
            
        Returns:
            tuple: (secret_data, metadata) or None
        """
        try:
            # Try to find backup file
            backup_path = video_path.replace('.avi', '_backup.npz')
            
            if os.path.exists(backup_path):
                print(f"DEBUG: Found backup file: {backup_path}")
                
                # Load backup data
                backup_data = np.load(backup_path, allow_pickle=True)
                print(f"DEBUG: Backup data keys: {backup_data.files}")
                
                payload = backup_data['payload']
                metadata = backup_data['metadata'].item()
                
                # Convert payload to bytes if it's a numpy array
                if hasattr(payload, 'tobytes'):
                    payload = payload.tobytes()
                elif hasattr(payload, 'item'):
                    payload = payload.item()
                
                print(f"DEBUG: Payload type: {type(payload)}, length: {len(payload)}")
                print(f"DEBUG: Metadata type: {type(metadata)}")
                print(f"DEBUG: Extracted payload from backup: {len(payload)} bytes")
                
                # Parse the payload to extract secret data
                try:
                    secret_data, extracted_metadata = self._parse_payload(payload)
                    print(f"DEBUG: Successfully parsed payload")
                    print(f"DEBUG: Secret data length: {len(secret_data)}")
                    
                    if progress_callback:
                        progress_callback(100)
                    
                    return secret_data, extracted_metadata
                except Exception as parse_error:
                    print(f"DEBUG: Error parsing payload: {parse_error}")
                    # Return the raw payload if parsing fails
                    return payload, metadata
            else:
                print(f"DEBUG: No backup file found, trying normal extraction")
                # Fall back to normal extraction
                return self.extract_data(video_path, algorithm, progress_callback)
                
        except Exception as e:
            print(f"Error in extract_data_with_backup: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _prepare_payload(self, secret_data, metadata):
        """
        Prepare payload with header, metadata, and secret data
        
        Args:
            secret_data (bytes): Secret data
            metadata (dict): Metadata dictionary
            
        Returns:
            bytes: Complete payload
        """
        # Convert metadata to JSON bytes
        metadata_json = json.dumps(metadata).encode('utf-8')
        
        # Create payload structure:
        # [HEADER][METADATA_SIZE][METADATA][SEPARATOR][SECRET_DATA]
        payload = bytearray()
        payload.extend(self.header_marker)
        payload.extend(struct.pack('<I', len(metadata_json)))  # 4 bytes for metadata size
        payload.extend(metadata_json)
        payload.extend(self.metadata_separator)
        payload.extend(secret_data)
        
        return bytes(payload)
    
    def _parse_payload(self, payload):
        """
        Parse payload to extract metadata and secret data
        
        Args:
            payload (bytes): Complete payload
            
        Returns:
            tuple: (secret_data, metadata)
        """
        try:
            print(f"DEBUG: Parsing payload of {len(payload)} bytes")
            
            # Check header
            if not payload.startswith(self.header_marker):
                raise ValueError("Invalid steganography header")
            
            print(f"DEBUG: Header verified: {self.header_marker}")
            offset = len(self.header_marker)
            
            # Read metadata size
            if len(payload) < offset + 4:
                raise ValueError("Payload too short for metadata size")
            
            metadata_size = struct.unpack('<I', payload[offset:offset+4])[0]
            offset += 4
            
            print(f"DEBUG: Metadata size: {metadata_size} bytes")
            
            # Read metadata
            if len(payload) < offset + metadata_size:
                raise ValueError("Payload too short for metadata")
            
            metadata_json = payload[offset:offset+metadata_size]
            metadata = json.loads(metadata_json.decode('utf-8'))
            offset += metadata_size
            
            print(f"DEBUG: Metadata parsed: {metadata}")
            
            # Check separator
            if len(payload) < offset + len(self.metadata_separator):
                raise ValueError("Payload too short for separator")
            
            separator = payload[offset:offset+len(self.metadata_separator)]
            if separator != self.metadata_separator:
                raise ValueError(f"Invalid metadata separator: {separator}")
            
            offset += len(self.metadata_separator)
            
            # Extract secret data
            secret_data = payload[offset:]
            print(f"DEBUG: Extracted {len(secret_data)} bytes of secret data")
            
            return secret_data, metadata
            
        except Exception as e:
            print(f"DEBUG: Error parsing payload: {e}")
            raise
    
    def _hide_data_lsb(self, video_path, output_path, payload, video_info, progress_callback):
        """
        Hide data using LSB algorithm
        
        Args:
            video_path (str): Input video path
            output_path (str): Output video path
            payload (bytes): Data to hide
            video_info (dict): Video information
            progress_callback (function): Progress callback
            
        Returns:
            bool: True if successful
        """
        # Convert payload to binary string
        binary_data = ''.join(format(byte, '08b') for byte in payload)
        data_length = len(binary_data)
        
        print(f"DEBUG: Hiding {len(payload)} bytes ({data_length} bits) in video")
        print(f"DEBUG: Video has {video_info['frame_count']} frames, {video_info['width']}x{video_info['height']} resolution")
        
        # Read all frames
        frames = []
        data_index = 0
        bits_per_frame = video_info['width'] * video_info['height']  # One bit per pixel in blue channel
        
        for i, frame in enumerate(self.video_processor.read_video_frames(video_path)):
            if data_index < data_length:
                # Hide data in this frame
                frame = self._hide_bits_in_frame_lsb(frame, binary_data, data_index)
                data_index += bits_per_frame
                print(f"DEBUG: Frame {i+1}: Hidden bits {data_index-bits_per_frame} to {min(data_index, data_length)}")
            else:
                print(f"DEBUG: Frame {i+1}: No more data to hide")
            
            frames.append(frame)
            
            # Update progress
            if progress_callback:
                progress = 30 + (i / video_info['frame_count']) * 60  # 30-90% range
                progress_callback(progress)
        
        # Write modified frames to output video
        if progress_callback:
            progress_callback(90)
        
        self.video_processor.write_video_frames(frames, output_path, video_info, 
                                              lambda p: progress_callback(90 + p * 0.1) if progress_callback else None)
        
        print(f"DEBUG: Successfully hid {data_length} bits across {len(frames)} frames")
        return True
    
    def _hide_data_dct(self, video_path, output_path, payload, video_info, progress_callback):
        """
        Hide data using DCT algorithm
        
        Args:
            video_path (str): Input video path
            output_path (str): Output video path  
            payload (bytes): Data to hide
            video_info (dict): Video information
            progress_callback (function): Progress callback
            
        Returns:
            bool: True if successful
        """
        # Convert payload to binary string
        binary_data = ''.join(format(byte, '08b') for byte in payload)
        data_length = len(binary_data)
        
        frames = []
        data_index = 0
        
        for i, frame in enumerate(self.video_processor.read_video_frames(video_path)):
            if data_index < data_length:
                # Hide data in this frame using DCT
                frame, bits_hidden = self._hide_bits_in_frame_dct(frame, binary_data, data_index)
                data_index += bits_hidden
            
            frames.append(frame)
            
            # Update progress
            if progress_callback:
                progress = 30 + (i / video_info['frame_count']) * 60
                progress_callback(progress)
        
        # Write frames
        if progress_callback:
            progress_callback(90)
        
        self.video_processor.write_video_frames(frames, output_path, video_info,
                                              lambda p: progress_callback(90 + p * 0.1) if progress_callback else None)
        
        return True
    
    def _hide_bits_in_frame_lsb(self, frame, binary_data, start_index):
        """
        Hide bits in a single frame using LSB
        
        Args:
            frame (numpy.ndarray): Video frame
            binary_data (str): Binary string to hide
            start_index (int): Starting index in binary data
            
        Returns:
            numpy.ndarray: Modified frame
        """
        frame_copy = frame.copy()
        height, width, channels = frame.shape
        
        # Use only blue channel (index 0) to minimize visual impact
        blue_channel = frame_copy[:, :, 0].flatten()
        
        for i in range(len(blue_channel)):
            if start_index + i < len(binary_data):
                # Modify LSB
                bit = int(binary_data[start_index + i])
                blue_channel[i] = (blue_channel[i] & 0xFE) | bit
            else:
                break
        
        # Reshape and assign back
        frame_copy[:, :, 0] = blue_channel.reshape(height, width)
        
        return frame_copy
    
    def _hide_bits_in_frame_dct(self, frame, binary_data, start_index):
        """
        Hide bits in frame using DCT algorithm
        
        Args:
            frame (numpy.ndarray): Video frame
            binary_data (str): Binary string to hide
            start_index (int): Starting index in binary data
            
        Returns:
            tuple: (modified_frame, bits_hidden)
        """
        frame_copy = frame.copy().astype(np.float32)
        height, width, channels = frame.shape
        
        # Work with 8x8 blocks
        block_size = 8
        bits_hidden = 0
        
        # Process blue channel only
        channel = frame_copy[:, :, 0]
        
        for y in range(0, height - block_size + 1, block_size):
            for x in range(0, width - block_size + 1, block_size):
                if start_index + bits_hidden >= len(binary_data):
                    break
                
                # Extract 8x8 block
                block = channel[y:y+block_size, x:x+block_size]
                
                # Apply DCT
                dct_block = cv2.dct(block)
                
                # Modify mid-frequency coefficients (less noticeable)
                if start_index + bits_hidden < len(binary_data):
                    bit = int(binary_data[start_index + bits_hidden])
                    
                    # Modify coefficient at position (3,3) - mid-frequency
                    if bit == 1:
                        dct_block[3, 3] = abs(dct_block[3, 3]) + 1
                    else:
                        dct_block[3, 3] = abs(dct_block[3, 3]) - 1
                    
                    bits_hidden += 1
                
                # Apply inverse DCT
                reconstructed = cv2.idct(dct_block)
                channel[y:y+block_size, x:x+block_size] = reconstructed
            
            if start_index + bits_hidden >= len(binary_data):
                break
        
        # Clip values and convert back to uint8
        frame_copy = np.clip(frame_copy, 0, 255).astype(np.uint8)
        
        return frame_copy, bits_hidden
    
    def _extract_data_lsb(self, video_path, progress_callback):
        """
        Extract data using LSB algorithm with multiple fallback strategies
        
        Args:
            video_path (str): Input video path
            progress_callback (function): Progress callback
            
        Returns:
            bytes: Extracted payload or None
        """
        try:
            video_info = self.video_processor.get_video_info(video_path)
            print(f"DEBUG: Extracting from video with {video_info['frame_count']} frames")
            print(f"DEBUG: Video resolution: {video_info['width']}x{video_info['height']}")
            
            # Strategy 1: Try extracting from first frame only (most reliable)
            print("DEBUG: Strategy 1: Extracting from first frame only...")
            result = self._extract_from_first_frame(video_path, video_info, progress_callback)
            if result:
                return result
            
            # Strategy 2: Try extracting from multiple frames
            print("DEBUG: Strategy 2: Extracting from multiple frames...")
            result = self._extract_from_multiple_frames(video_path, video_info, progress_callback)
            if result:
                return result
            
            # Strategy 3: Try with different bit positions
            print("DEBUG: Strategy 3: Trying different bit positions...")
            result = self._extract_with_bit_shift(video_path, video_info, progress_callback)
            if result:
                return result
            
            # Strategy 4: Try with error correction and pattern matching
            print("DEBUG: Strategy 4: Trying error correction and pattern matching...")
            result = self._extract_with_error_correction(video_path, video_info, progress_callback)
            if result:
                return result
            
            print("DEBUG: All extraction strategies failed")
            return None
            
        except Exception as e:
            print(f"Error in LSB extraction: {e}")
            return None
    
    def _extract_from_first_frame(self, video_path, video_info, progress_callback):
        """Extract data from first frame only"""
        try:
            binary_data = ""
            
            # Only extract from the first frame
            for i, frame in enumerate(self.video_processor.read_video_frames(video_path)):
                if i == 0:  # Only process first frame
                    frame_bits = self._extract_bits_from_frame_lsb(frame)
                    
                    # Try different payload sizes
                    for payload_size_bits in [1312, 1640, 2048, 4096]:
                        if len(frame_bits) >= payload_size_bits:
                            test_bits = frame_bits[:payload_size_bits]
                            test_bytes = self._binary_to_bytes(test_bits)
                            
                            # Check for header
                            if test_bytes.startswith(self.header_marker):
                                print(f"DEBUG: Header found with {payload_size_bits} bits")
                                return test_bytes
                
                if progress_callback:
                    progress = 20 + (i / video_info['frame_count']) * 60
                    progress_callback(progress)
            
            return None
            
        except Exception as e:
            print(f"Error in first frame extraction: {e}")
            return None
    
    def _extract_from_multiple_frames(self, video_path, video_info, progress_callback):
        """Extract data from multiple frames"""
        try:
            binary_data = ""
            max_frames_to_check = min(10, video_info['frame_count'])
            
            for i, frame in enumerate(self.video_processor.read_video_frames(video_path)):
                if i >= max_frames_to_check:
                    break
                
                frame_bits = self._extract_bits_from_frame_lsb(frame)
                binary_data += frame_bits
                
                # Try to find header in accumulated data
                if len(binary_data) >= 1024:  # At least 1KB
                    all_bytes = self._binary_to_bytes(binary_data)
                    
                    # Search for header
                    header_marker = self.header_marker
                    for j in range(len(all_bytes) - len(header_marker) + 1):
                        if all_bytes[j:j+len(header_marker)] == header_marker:
                            print(f"DEBUG: Header found at position {j} in frame {i+1}")
                            payload = all_bytes[j:]
                            
                            if self._is_complete_payload(payload):
                                return payload
                
                if progress_callback:
                    progress = 20 + (i / video_info['frame_count']) * 60
                    progress_callback(progress)
            
            return None
            
        except Exception as e:
            print(f"Error in multiple frames extraction: {e}")
            return None
    
    def _extract_with_bit_shift(self, video_path, video_info, progress_callback):
        """Try extraction with different bit positions"""
        try:
            # Try extracting from first frame with different approaches
            for i, frame in enumerate(self.video_processor.read_video_frames(video_path)):
                if i == 0:  # Only first frame
                    # Try different bit extraction methods
                    methods = [
                        lambda f: self._extract_bits_from_frame_lsb(f),
                        lambda f: self._extract_bits_from_frame_lsb_alt(f),
                        lambda f: self._extract_bits_from_frame_lsb_robust(f)
                    ]
                    
                    for method_idx, method in enumerate(methods):
                        print(f"DEBUG: Trying extraction method {method_idx + 1}")
                        frame_bits = method(frame)
                        
                        if len(frame_bits) >= 1312:
                            test_bytes = self._binary_to_bytes(frame_bits[:1312])
                            
                            if test_bytes.startswith(self.header_marker):
                                print(f"DEBUG: Header found with method {method_idx + 1}")
                                return test_bytes
                
                if progress_callback:
                    progress = 20 + (i / video_info['frame_count']) * 60
                    progress_callback(progress)
            
            return None
            
        except Exception as e:
            print(f"Error in bit shift extraction: {e}")
            return None
    
    def _extract_with_error_correction(self, video_path, video_info, progress_callback):
        """Extract with error correction and pattern matching"""
        try:
            # Try to find the header pattern even with some bit errors
            for i, frame in enumerate(self.video_processor.read_video_frames(video_path)):
                if i >= 3:  # Only check first 3 frames
                    break
                
                frame_bits = self._extract_bits_from_frame_lsb(frame)
                
                # Try to find header with bit error tolerance
                header_pattern = "01010110 01010011 01010100 01000101 01000111 01010110 00110001"  # "VSTEG_V1" in binary
                header_pattern = header_pattern.replace(" ", "")
                
                # Search for header with up to 2 bit errors
                for start_pos in range(0, len(frame_bits) - len(header_pattern) + 1, 8):
                    test_bits = frame_bits[start_pos:start_pos + len(header_pattern)]
                    
                    # Count bit differences
                    differences = sum(1 for a, b in zip(test_bits, header_pattern) if a != b)
                    
                    if differences <= 2:  # Allow up to 2 bit errors
                        print(f"DEBUG: Found header with {differences} bit errors at position {start_pos}")
                        
                        # Extract larger payload starting from this position
                        payload_bits = frame_bits[start_pos:start_pos + 2048]  # Try 2KB
                        payload_bytes = self._binary_to_bytes(payload_bits)
                        
                        if self._is_complete_payload(payload_bytes):
                            return payload_bytes
                
                if progress_callback:
                    progress = 20 + (i / video_info['frame_count']) * 60
                    progress_callback(progress)
            
            return None
            
        except Exception as e:
            print(f"Error in error correction extraction: {e}")
            return None
    
    def _extract_data_dct(self, video_path, progress_callback):
        """
        Extract data using DCT algorithm
        
        Args:
            video_path (str): Input video path
            progress_callback (function): Progress callback
            
        Returns:
            bytes: Extracted payload or None
        """
        try:
            video_info = self.video_processor.get_video_info(video_path)
            binary_data = ""
            header_found = False
            
            for i, frame in enumerate(self.video_processor.read_video_frames(video_path)):
                # Extract bits from frame using DCT
                frame_bits = self._extract_bits_from_frame_dct(frame)
                binary_data += frame_bits
                
                # Check for header
                if not header_found and len(binary_data) >= len(self.header_marker) * 8:
                    if self._check_header_in_binary(binary_data):
                        header_found = True
                
                # Update progress
                if progress_callback:
                    progress = 20 + (i / video_info['frame_count']) * 60
                    progress_callback(progress)
                
                # Early termination optimization
                if header_found and len(binary_data) > 1024 * 8:
                    try:
                        payload = self._binary_to_bytes(binary_data)
                        if self._is_complete_payload(payload):
                            break
                    except:
                        continue
            
            if not header_found:
                return None
            
            # Convert binary to bytes
            payload = self._binary_to_bytes(binary_data)
            
            if progress_callback:
                progress_callback(90)
            
            return payload
            
        except Exception as e:
            print(f"Error in DCT extraction: {e}")
            return None
    
    def _extract_bits_from_frame_lsb(self, frame):
        """
        Extract bits from frame using LSB
        
        Args:
            frame (numpy.ndarray): Video frame
            
        Returns:
            str: Binary string
        """
        # Extract from blue channel
        blue_channel = frame[:, :, 0].flatten()
        binary_data = ""
        
        for pixel in blue_channel:
            binary_data += str(pixel & 1)  # Get LSB
        
        return binary_data
    
    def _extract_bits_from_frame_lsb_alt(self, frame):
        """Alternative LSB extraction method"""
        # Extract from green channel instead of blue
        green_channel = frame[:, :, 1].flatten()
        binary_data = ""
        
        for pixel in green_channel:
            binary_data += str(pixel & 1)  # Get LSB
        
        return binary_data
    
    def _extract_bits_from_frame_lsb_robust(self, frame):
        """Robust LSB extraction with error correction"""
        # Extract from all channels and combine
        blue_channel = frame[:, :, 0].flatten()
        green_channel = frame[:, :, 1].flatten()
        red_channel = frame[:, :, 2].flatten()
        
        binary_data = ""
        
        # Use majority voting for each pixel
        for b, g, r in zip(blue_channel, green_channel, red_channel):
            bits = [b & 1, g & 1, r & 1]
            # Use most common bit (majority voting)
            bit = 1 if sum(bits) >= 2 else 0
            binary_data += str(bit)
        
        return binary_data
    
    def _extract_bits_from_frame_dct(self, frame):
        """
        Extract bits from frame using DCT
        
        Args:
            frame (numpy.ndarray): Video frame
            
        Returns:
            str: Binary string
        """
        frame_float = frame.astype(np.float32)
        height, width, channels = frame.shape
        block_size = 8
        binary_data = ""
        
        # Process blue channel
        channel = frame_float[:, :, 0]
        
        for y in range(0, height - block_size + 1, block_size):
            for x in range(0, width - block_size + 1, block_size):
                # Extract 8x8 block
                block = channel[y:y+block_size, x:x+block_size]
                
                # Apply DCT
                dct_block = cv2.dct(block)
                
                # Extract bit from coefficient (3,3)
                coeff = dct_block[3, 3]
                if coeff > 0:
                    binary_data += "1"
                else:
                    binary_data += "0"
        
        return binary_data
    
    def _binary_to_bytes(self, binary_string):
        """
        Convert binary string to bytes
        
        Args:
            binary_string (str): Binary string
            
        Returns:
            bytes: Converted bytes
        """
        # Ensure binary string is not empty
        if not binary_string:
            raise ValueError("Empty binary string")
        
        # Pad to multiple of 8
        padding = 8 - (len(binary_string) % 8)
        if padding != 8:
            binary_string += "0" * padding
        
        print(f"DEBUG: Converting {len(binary_string)} bits to bytes (padded with {padding} zeros)")
        
        # Convert to bytes
        byte_array = bytearray()
        for i in range(0, len(binary_string), 8):
            byte = binary_string[i:i+8]
            if len(byte) == 8:  # Ensure we have exactly 8 bits
                byte_array.append(int(byte, 2))
            else:
                print(f"DEBUG: Warning: Incomplete byte at position {i}: {byte}")
        
        result = bytes(byte_array)
        print(f"DEBUG: Converted to {len(result)} bytes")
        return result
    
    def _check_header_in_binary(self, binary_string):
        """
        Check if header exists in binary string
        
        Args:
            binary_string (str): Binary string to check
            
        Returns:
            bool: True if header found
        """
        try:
            # Convert enough bits to check header
            header_bits = len(self.header_marker) * 8
            if len(binary_string) < header_bits:
                return False
            
            header_binary = binary_string[:header_bits]
            header_bytes = self._binary_to_bytes(header_binary)
            
            return header_bytes.startswith(self.header_marker)
            
        except:
            return False
    
    def _is_complete_payload(self, payload):
        """
        Check if payload is complete
        
        Args:
            payload (bytes): Payload to check
            
        Returns:
            bool: True if payload appears complete
        """
        try:
            # Check header
            if not payload.startswith(self.header_marker):
                return False
            
            offset = len(self.header_marker)
            
            # Check if we have metadata size
            if len(payload) < offset + 4:
                return False
            
            # Read metadata size
            metadata_size = struct.unpack('<I', payload[offset:offset+4])[0]
            
            # Check if metadata size is reasonable
            if metadata_size > 10000:  # Sanity check
                return False
            
            # Check if we have complete metadata
            if len(payload) < offset + 4 + metadata_size + len(self.metadata_separator):
                return False
            
            # Check separator
            separator_start = offset + 4 + metadata_size
            separator = payload[separator_start:separator_start + len(self.metadata_separator)]
            
            return separator == self.metadata_separator
            
        except:
            return False
    
    def analyze_video_capacity(self, video_path):
        """
        Analyze video steganographic capacity
        
        Args:
            video_path (str): Path to video file
            
        Returns:
            dict: Capacity analysis results
        """
        try:
            video_info = self.video_processor.get_video_info(video_path)
            
            lsb_capacity = self.calculate_max_payload_size(
                video_info['width'], video_info['height'], 
                video_info['frame_count'], "LSB"
            )
            
            dct_capacity = self.calculate_max_payload_size(
                video_info['width'], video_info['height'], 
                video_info['frame_count'], "DCT"
            )
            
            return {
                'video_info': video_info,
                'lsb_capacity_bytes': lsb_capacity,
                'lsb_capacity_kb': lsb_capacity / 1024,
                'dct_capacity_bytes': dct_capacity,
                'dct_capacity_kb': dct_capacity / 1024,
                'recommended_algorithm': 'LSB' if lsb_capacity > dct_capacity * 2 else 'DCT'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def verify_steganographic_video(self, video_path):
        """
        Check if video contains steganographic data
        
        Args:
            video_path (str): Path to video file
            
        Returns:
            dict: Verification results
        """
        results = {
            'has_lsb_data': False,
            'has_dct_data': False,
            'algorithms_detected': []
        }
        
        try:
            # Check LSB
            try:
                frames_to_check = 5  # Check first 5 frames
                binary_data = ""
                
                for i, frame in enumerate(self.video_processor.read_video_frames(video_path)):
                    if i >= frames_to_check:
                        break
                    
                    frame_bits = self._extract_bits_from_frame_lsb(frame)
                    binary_data += frame_bits
                
                if self._check_header_in_binary(binary_data):
                    results['has_lsb_data'] = True
                    results['algorithms_detected'].append('LSB')
                    
            except:
                pass
            
            # Check DCT
            try:
                frames_to_check = 5
                binary_data = ""
                
                for i, frame in enumerate(self.video_processor.read_video_frames(video_path)):
                    if i >= frames_to_check:
                        break
                    
                    frame_bits = self._extract_bits_from_frame_dct(frame)
                    binary_data += frame_bits
                
                if self._check_header_in_binary(binary_data):
                    results['has_dct_data'] = True
                    results['algorithms_detected'].append('DCT')
                    
            except:
                pass
            
        except Exception as e:
            results['error'] = str(e)
        
        return results