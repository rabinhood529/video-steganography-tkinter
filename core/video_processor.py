"""
Video processing utilities for steganography operations.
"""

import cv2
import numpy as np
from typing import Tuple, Optional, Dict, Any
from utils.logger import get_logger

logger = get_logger(__name__)


class VideoProcessor:
    """Handles video processing and capacity calculations."""
    
    def __init__(self):
        self.video_info = {}
    
    def get_video_properties(self, video_path: str) -> Optional[Dict[str, Any]]:
        """
        Extract video properties including resolution, fps, duration, and frame count.
        
        Args:
            video_path: Path to video file
            
        Returns:
            Dictionary with video properties or None if error
        """
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                logger.error(f"Could not open video: {video_path}")
                return None
            
            # Get video properties
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            
            # Calculate duration
            duration = frame_count / fps if fps > 0 else 0
            
            # Determine resolution category
            resolution_category = self._get_resolution_category(width, height)
            
            properties = {
                'width': width,
                'height': height,
                'fps': fps,
                'frame_count': frame_count,
                'duration': duration,
                'resolution_category': resolution_category,
                'total_pixels': width * height * frame_count
            }
            
            cap.release()
            self.video_info = properties
            
            logger.info(f"Video properties: {width}x{height}, {fps:.2f} FPS, "
                       f"{frame_count} frames, {duration:.2f}s")
            
            return properties
            
        except Exception as e:
            logger.error(f"Error getting video properties: {e}")
            return None
    
    def _get_resolution_category(self, width: int, height: int) -> str:
        """Categorize video resolution."""
        if width <= 854 and height <= 480:
            return "480p"
        elif width <= 1280 and height <= 720:
            return "720p"
        elif width <= 1920 and height <= 1080:
            return "1080p"
        else:
            return "Higher than 1080p"
    
    def calculate_max_capacity(self, video_path: str, algorithm: str = "LSB") -> int:
        """
        Calculate maximum data capacity for the video.
        
        Args:
            video_path: Path to video file
            algorithm: Steganography algorithm ("LSB" or "DCT")
            
        Returns:
            Maximum capacity in bytes
        """
        properties = self.get_video_properties(video_path)
        if not properties:
            return 0
        
        try:
            if algorithm.upper() == "LSB":
                # LSB can use 1 bit per color channel per pixel
                # RGB = 3 channels, so 3 bits per pixel
                bits_per_pixel = 3
                total_bits = properties['total_pixels'] * bits_per_pixel
                
                # Reserve space for metadata (file extension, size, etc.)
                metadata_bits = 1024 * 8  # 1KB for metadata
                usable_bits = max(0, total_bits - metadata_bits)
                
                capacity_bytes = usable_bits // 8
                
            elif algorithm.upper() == "DCT":
                # DCT embedding is more conservative
                # Assume we can embed in ~10% of DCT coefficients
                total_blocks = (properties['width'] // 8) * (properties['height'] // 8)
                total_blocks *= properties['frame_count']
                
                # Each 8x8 block can hold ~4 bits safely
                bits_per_block = 4
                total_bits = total_blocks * bits_per_block
                
                # Reserve metadata space
                metadata_bits = 1024 * 8
                usable_bits = max(0, total_bits - metadata_bits)
                
                capacity_bytes = usable_bits // 8
                
            else:
                logger.error(f"Unknown algorithm: {algorithm}")
                return 0
            
            logger.info(f"Calculated max capacity for {algorithm}: {capacity_bytes} bytes")
            return capacity_bytes
            
        except Exception as e:
            logger.error(f"Error calculating capacity: {e}")
            return 0
    
    def load_video_frames(self, video_path: str) -> Optional[np.ndarray]:
        """
        Load all video frames into memory.
        
        Args:
            video_path: Path to video file
            
        Returns:
            Array of frames or None if error
        """
        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                logger.error(f"Could not open video: {video_path}")
                return None
            
            frames = []
            frame_count = 0
            
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                frames.append(frame)
                frame_count += 1
                
                # Log progress for large videos
                if frame_count % 100 == 0:
                    logger.info(f"Loaded {frame_count} frames...")
            
            cap.release()
            
            if not frames:
                logger.error("No frames loaded from video")
                return None
            
            logger.info(f"Successfully loaded {len(frames)} frames")
            return np.array(frames)
            
        except Exception as e:
            logger.error(f"Error loading video frames: {e}")
            return None
    
    def save_video_frames(self, frames: np.ndarray, output_path: str, 
                         fps: float, codec: str = 'mp4v') -> bool:
        """
        Save frames as video file.
        
        Args:
            frames: Array of video frames
            output_path: Output video path
            fps: Frames per second
            codec: Video codec
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if len(frames) == 0:
                logger.error("No frames to save")
                return False
            
            height, width = frames[0].shape[:2]
            
            # Define codec and create VideoWriter
            fourcc = cv2.VideoWriter_fourcc(*codec)
            out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
            
            if not out.isOpened():
                logger.error(f"Could not open video writer for {output_path}")
                return False
            
            frame_count = 0
            for frame in frames:
                out.write(frame)
                frame_count += 1
                
                # Log progress
                if frame_count % 100 == 0:
                    logger.info(f"Saved {frame_count}/{len(frames)} frames...")
            
            out.release()
            logger.info(f"Successfully saved video with {len(frames)} frames to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving video: {e}")
            return False
    
    def validate_video_compatibility(self, video_path: str) -> Tuple[bool, str]:
        """
        Validate if video is compatible for steganography.
        
        Args:
            video_path: Path to video file
            
        Returns:
            Tuple of (is_compatible, error_message)
        """
        properties = self.get_video_properties(video_path)
        if not properties:
            return False, "Could not read video properties"
        
        # Check resolution limits
        if properties['resolution_category'] not in ["480p", "720p", "1080p"]:
            return False, f"Unsupported resolution: {properties['resolution_category']}"
        
        # Check if video has frames
        if properties['frame_count'] == 0:
            return False, "Video has no frames"
        
        # Check duration (should be reasonable)
        if properties['duration'] < 0.1:
            return False, "Video too short for steganography"
        
        # Check FPS
        if properties['fps'] <= 0:
            return False, "Invalid frame rate"
        
        return True, ""
    
    def get_capacity_info(self, video_path: str) -> Dict[str, Any]:
        """
        Get comprehensive capacity information for both algorithms.
        
        Args:
            video_path: Path to video file
            
        Returns:
            Dictionary with capacity information
        """
        try:
            properties = self.get_video_properties(video_path)
            if not properties:
                return {}
            
            lsb_capacity = self.calculate_max_capacity(video_path, "LSB")
            dct_capacity = self.calculate_max_capacity(video_path, "DCT")
            
            return {
                'video_properties': properties,
                'lsb_capacity_bytes': lsb_capacity,
                'dct_capacity_bytes': dct_capacity,
                'lsb_capacity_formatted': self._format_bytes(lsb_capacity),
                'dct_capacity_formatted': self._format_bytes(dct_capacity)
            }
            
        except Exception as e:
            logger.error(f"Error getting capacity info: {e}")
            return {}
    
    def _format_bytes(self, bytes_size: int) -> str:
        """Format bytes in human-readable format."""
        if bytes_size < 1024:
            return f"{bytes_size} B"
        elif bytes_size < 1024 * 1024:
            return f"{bytes_size / 1024:.1f} KB"
        elif bytes_size < 1024 * 1024 * 1024:
            return f"{bytes_size / (1024 * 1024):.1f} MB"
        else:
            return f"{bytes_size / (1024 * 1024 * 1024):.1f} GB"