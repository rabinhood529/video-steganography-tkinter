"""
Video Processing Utilities
Handles video metadata extraction, validation, and format conversion.
"""

import cv2
import os
import logging
from typing import Dict, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class VideoMetadata:
    """Video metadata container"""
    width: int
    height: int
    fps: float
    frame_count: int
    duration: float
    file_size: int
    format: str
    codec: str
    bitrate: Optional[int] = None


class VideoProcessor:
    """Video processing and validation utilities"""
    
    SUPPORTED_FORMATS = ['.mp4', '.avi', '.mov', '.mkv', '.wmv']
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    SUPPORTED_RESOLUTIONS = {
        '480p': (854, 480),
        '720p': (1280, 720),
        '1080p': (1920, 1080)
    }
    
    @staticmethod
    def get_video_metadata(video_path: str) -> VideoMetadata:
        """
        Extract comprehensive metadata from video file
        
        Args:
            video_path: Path to video file
            
        Returns:
            VideoMetadata object with video information
        """
        try:
            if not os.path.exists(video_path):
                raise FileNotFoundError(f"Video file not found: {video_path}")
            
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise ValueError(f"Cannot open video file: {video_path}")
            
            # Basic properties
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            # Calculate duration
            duration = frame_count / fps if fps > 0 else 0
            
            # File information
            file_size = os.path.getsize(video_path)
            file_format = os.path.splitext(video_path)[1].lower()
            
            # Try to get codec information
            fourcc = cap.get(cv2.CAP_PROP_FOURCC)
            codec = "".join([chr((int(fourcc) >> 8 * i) & 0xFF) for i in range(4)])
            
            # Estimate bitrate
            bitrate = None
            if duration > 0:
                bitrate = int((file_size * 8) / duration)  # bits per second
            
            cap.release()
            
            metadata = VideoMetadata(
                width=width,
                height=height,
                fps=fps,
                frame_count=frame_count,
                duration=duration,
                file_size=file_size,
                format=file_format,
                codec=codec,
                bitrate=bitrate
            )
            
            logger.info(f"Video metadata extracted: {width}x{height}, {fps}fps, {duration:.2f}s")
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to extract video metadata: {e}")
            raise
    
    @staticmethod
    def validate_video(video_path: str) -> Tuple[bool, str]:
        """
        Validate video file for steganography compatibility
        
        Args:
            video_path: Path to video file
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            if not os.path.exists(video_path):
                return False, "Video file does not exist"
            
            # Check file size
            file_size = os.path.getsize(video_path)
            if file_size > VideoProcessor.MAX_FILE_SIZE:
                size_mb = file_size / (1024 * 1024)
                return False, f"Video file too large: {size_mb:.1f}MB (max 50MB)"
            
            # Check file format
            file_ext = os.path.splitext(video_path)[1].lower()
            if file_ext not in VideoProcessor.SUPPORTED_FORMATS:
                return False, f"Unsupported video format: {file_ext}"
            
            # Get metadata
            metadata = VideoProcessor.get_video_metadata(video_path)
            
            # Check resolution
            resolution_valid = False
            for res_name, (w, h) in VideoProcessor.SUPPORTED_RESOLUTIONS.items():
                if metadata.width == w and metadata.height == h:
                    resolution_valid = True
                    break
            
            if not resolution_valid:
                return False, f"Unsupported resolution: {metadata.width}x{metadata.height}"
            
            # Check if video has frames
            if metadata.frame_count == 0:
                return False, "Video has no frames"
            
            # Check duration
            if metadata.duration == 0:
                return False, "Video duration is zero"
            
            return True, "Video is valid for steganography"
            
        except Exception as e:
            logger.error(f"Video validation failed: {e}")
            return False, f"Validation error: {str(e)}"
    
    @staticmethod
    def get_resolution_name(width: int, height: int) -> str:
        """
        Get resolution name from dimensions
        
        Args:
            width: Video width
            height: Video height
            
        Returns:
            Resolution name (e.g., "720p") or "Custom"
        """
        for res_name, (w, h) in VideoProcessor.SUPPORTED_RESOLUTIONS.items():
            if width == w and height == h:
                return res_name
        return f"Custom ({width}x{height})"
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """
        Format file size in human-readable format
        
        Args:
            size_bytes: Size in bytes
            
        Returns:
            Formatted size string
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """
        Format duration in human-readable format
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            Formatted duration string (HH:MM:SS)
        """
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        else:
            return f"{minutes:02d}:{secs:02d}"
    
    @staticmethod
    def calculate_steganography_capacity(metadata: VideoMetadata, method: str = "LSB") -> int:
        """
        Calculate steganography capacity for a video
        
        Args:
            metadata: Video metadata
            method: Steganography method ("LSB" or "DCT")
            
        Returns:
            Maximum capacity in bytes
        """
        try:
            if method.upper() == "LSB":
                # LSB: 1 bit per pixel per channel
                pixels_per_frame = metadata.width * metadata.height * 3  # RGB
                total_bits = metadata.frame_count * pixels_per_frame
                capacity = total_bits // 8  # Convert to bytes
            else:  # DCT
                # DCT: 1 bit per 8x8 block
                blocks_per_frame = (metadata.width // 8) * (metadata.height // 8)
                total_bits = metadata.frame_count * blocks_per_frame
                capacity = total_bits // 8  # Convert to bytes
            
            # Reserve space for metadata overhead
            metadata_overhead = 1024  # 1KB
            capacity = max(0, capacity - metadata_overhead)
            
            logger.info(f"Calculated capacity: {capacity} bytes using {method}")
            return capacity
            
        except Exception as e:
            logger.error(f"Capacity calculation failed: {e}")
            return 0
    
    @staticmethod
    def estimate_embedding_time(metadata: VideoMetadata, method: str = "LSB") -> float:
        """
        Estimate time required for embedding process
        
        Args:
            metadata: Video metadata
            method: Steganography method
            
        Returns:
            Estimated time in seconds
        """
        # Base processing time per frame (rough estimates)
        if method.upper() == "LSB":
            time_per_frame = 0.01  # 10ms per frame for LSB
        else:  # DCT
            time_per_frame = 0.05  # 50ms per frame for DCT (more complex)
        
        # Factor in resolution complexity
        pixel_count = metadata.width * metadata.height
        resolution_factor = pixel_count / (1280 * 720)  # Normalize to 720p
        
        estimated_time = metadata.frame_count * time_per_frame * resolution_factor
        return max(1.0, estimated_time)  # Minimum 1 second


class FileValidator:
    """Utility class for validating secret files"""
    
    SUPPORTED_TEXT_FORMATS = ['.txt', '.doc', '.docx']
    SUPPORTED_IMAGE_FORMATS = ['.jpg', '.jpeg', '.png', '.bmp', '.gif']
    SUPPORTED_VIDEO_FORMATS = ['.mp4', '.avi', '.mov', '.mkv']
    
    @staticmethod
    def validate_secret_file(file_path: str) -> Tuple[bool, str, str]:
        """
        Validate secret file for embedding
        
        Args:
            file_path: Path to secret file
            
        Returns:
            Tuple of (is_valid, file_type, error_message)
        """
        try:
            if not os.path.exists(file_path):
                return False, "unknown", "File does not exist"
            
            file_ext = os.path.splitext(file_path)[1].lower()
            file_size = os.path.getsize(file_path)
            
            # Determine file type
            if file_ext in FileValidator.SUPPORTED_TEXT_FORMATS:
                file_type = "text"
            elif file_ext in FileValidator.SUPPORTED_IMAGE_FORMATS:
                file_type = "image"
            elif file_ext in FileValidator.SUPPORTED_VIDEO_FORMATS:
                file_type = "video"
            else:
                return False, "unknown", f"Unsupported file format: {file_ext}"
            
            # Check file size (reasonable limits)
            max_sizes = {
                "text": 10 * 1024 * 1024,    # 10MB for text files
                "image": 20 * 1024 * 1024,   # 20MB for images
                "video": 30 * 1024 * 1024    # 30MB for videos
            }
            
            if file_size > max_sizes[file_type]:
                size_mb = file_size / (1024 * 1024)
                max_mb = max_sizes[file_type] / (1024 * 1024)
                return False, file_type, f"File too large: {size_mb:.1f}MB (max {max_mb}MB for {file_type})"
            
            return True, file_type, "File is valid for embedding"
            
        except Exception as e:
            logger.error(f"Secret file validation failed: {e}")
            return False, "unknown", f"Validation error: {str(e)}"