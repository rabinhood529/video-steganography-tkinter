"""
Video Processor Module
Handles video file operations, metadata extraction, and frame processing

Author: AI Assistant
"""

import cv2
import numpy as np
import os
from pathlib import Path


class VideoProcessor:
    """Handles video file operations and metadata extraction"""
    
    def __init__(self):
        self.supported_formats = ['.mp4', '.avi', '.mov', '.mkv']
    
    def get_video_info(self, video_path):
        """
        Extract comprehensive video information
        
        Args:
            video_path (str): Path to video file
            
        Returns:
            dict: Video information including resolution, fps, duration, etc.
        """
        if not os.path.exists(video_path):
            raise FileNotFoundError(f"Video file not found: {video_path}")
        
        # Check file extension
        file_ext = Path(video_path).suffix.lower()
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported video format: {file_ext}")
        
        # Open video
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise ValueError(f"Cannot open video file: {video_path}")
        
        try:
            # Get video properties
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            # Calculate duration
            duration = frame_count / fps if fps > 0 else 0
            
            # Get codec information
            fourcc = int(cap.get(cv2.CAP_PROP_FOURCC))
            codec = "".join([chr((fourcc >> 8 * i) & 0xFF) for i in range(4)])
            
            # Get file size
            file_size = os.path.getsize(video_path)
            
            # Validate resolution
            if not self.is_supported_resolution(width, height):
                print(f"Warning: Resolution {width}x{height} may not be optimal for steganography")
            
            video_info = {
                'width': width,
                'height': height,
                'fps': fps,
                'frame_count': frame_count,
                'duration': duration,
                'codec': codec.strip('\x00'),
                'file_size': file_size,
                'format': file_ext,
                'path': video_path
            }
            
            return video_info
            
        finally:
            cap.release()
    
    def is_supported_resolution(self, width, height):
        """
        Check if resolution is supported (480p, 720p, 1080p)
        
        Args:
            width (int): Video width
            height (int): Video height
            
        Returns:
            bool: True if resolution is supported
        """
        supported_resolutions = [
            (854, 480),   # 480p
            (1280, 720),  # 720p
            (1920, 1080), # 1080p
            (640, 480),   # VGA
            (720, 480),   # NTSC
            (1366, 768),  # Common laptop resolution
        ]
        
        return (width, height) in supported_resolutions or height in [480, 720, 1080]
    
    def read_video_frames(self, video_path, progress_callback=None):
        """
        Read all frames from video
        
        Args:
            video_path (str): Path to video file
            progress_callback (function): Callback for progress updates
            
        Yields:
            numpy.ndarray: Video frame
        """
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise ValueError(f"Cannot open video: {video_path}")
        
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        frame_index = 0
        
        try:
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                
                yield frame
                frame_index += 1
                
                # Update progress
                if progress_callback and frame_count > 0:
                    progress = (frame_index / frame_count) * 100
                    progress_callback(progress)
                    
        finally:
            cap.release()
    
    def write_video_frames(self, frames, output_path, video_info, progress_callback=None):
        """
        Write frames to video file
        
        Args:
            frames (list): List of video frames (numpy arrays)
            output_path (str): Output video path
            video_info (dict): Video information
            progress_callback (function): Progress callback function
        """
        if not frames:
            raise ValueError("No frames to write")
        
        # Get video properties
        height, width, channels = frames[0].shape
        fps = video_info.get('fps', 30.0)
        
        # Use lossless codec to preserve LSB data
        if output_path.endswith('.mp4'):
            # Use uncompressed for MP4 (not ideal but better than compressed)
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        elif output_path.endswith('.avi'):
            # Use uncompressed AVI to preserve LSB data
            fourcc = cv2.VideoWriter_fourcc(*'IYUV')
        else:
            # Default to uncompressed
            fourcc = cv2.VideoWriter_fourcc(*'IYUV')
        
        # Create video writer
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        
        if not out.isOpened():
            raise ValueError(f"Cannot create video writer for {output_path}")
        
        try:
            # Write frames
            for i, frame in enumerate(frames):
                out.write(frame)
                
                # Update progress
                if progress_callback:
                    progress = (i / len(frames)) * 100
                    progress_callback(progress)
                    
        finally:
            out.release()
    
    def validate_video_file(self, video_path, max_size_mb=50):
        """
        Validate video file for steganography
        
        Args:
            video_path (str): Path to video file
            max_size_mb (int): Maximum file size in MB
            
        Returns:
            tuple: (is_valid, error_message)
        """
        try:
            # Check if file exists
            if not os.path.exists(video_path):
                return False, "File does not exist"
            
            # Check file size
            file_size_mb = os.path.getsize(video_path) / (1024 * 1024)
            if file_size_mb > max_size_mb:
                return False, f"File too large: {file_size_mb:.1f} MB (max: {max_size_mb} MB)"
            
            # Check format
            file_ext = Path(video_path).suffix.lower()
            if file_ext not in self.supported_formats:
                return False, f"Unsupported format: {file_ext}"
            
            # Try to open video
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return False, "Cannot open video file - may be corrupted"
            
            # Check basic properties
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            
            cap.release()
            
            if width <= 0 or height <= 0:
                return False, "Invalid video dimensions"
            
            if frame_count <= 0:
                return False, "No frames found in video"
            
            return True, "Video file is valid"
            
        except Exception as e:
            return False, f"Error validating video: {str(e)}"
    
    def extract_frame(self, video_path, frame_number):
        """
        Extract a specific frame from video
        
        Args:
            video_path (str): Path to video file
            frame_number (int): Frame number to extract
            
        Returns:
            numpy.ndarray: Extracted frame
        """
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise ValueError(f"Cannot open video: {video_path}")
        
        try:
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_number)
            ret, frame = cap.read()
            
            if not ret:
                raise ValueError(f"Cannot read frame {frame_number}")
            
            return frame
            
        finally:
            cap.release()
    
    def get_frame_at_time(self, video_path, time_seconds):
        """
        Extract frame at specific time
        
        Args:
            video_path (str): Path to video file
            time_seconds (float): Time in seconds
            
        Returns:
            numpy.ndarray: Frame at specified time
        """
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise ValueError(f"Cannot open video: {video_path}")
        
        try:
            # Set position in milliseconds
            cap.set(cv2.CAP_PROP_POS_MSEC, time_seconds * 1000)
            ret, frame = cap.read()
            
            if not ret:
                raise ValueError(f"Cannot read frame at time {time_seconds}s")
            
            return frame
            
        finally:
            cap.release()
    
    def calculate_video_quality_metrics(self, original_path, modified_path):
        """
        Calculate quality metrics between original and modified video
        
        Args:
            original_path (str): Path to original video
            modified_path (str): Path to modified video
            
        Returns:
            dict: Quality metrics (PSNR, MSE, etc.)
        """
        cap1 = cv2.VideoCapture(original_path)
        cap2 = cv2.VideoCapture(modified_path)
        
        if not cap1.isOpened() or not cap2.isOpened():
            raise ValueError("Cannot open video files for comparison")
        
        psnr_values = []
        mse_values = []
        frame_count = 0
        
        try:
            while True:
                ret1, frame1 = cap1.read()
                ret2, frame2 = cap2.read()
                
                if not ret1 or not ret2:
                    break
                
                # Convert to grayscale for comparison
                gray1 = cv2.cvtColor(frame1, cv2.COLOR_BGR2GRAY)
                gray2 = cv2.cvtColor(frame2, cv2.COLOR_BGR2GRAY)
                
                # Calculate MSE
                mse = np.mean((gray1.astype(float) - gray2.astype(float)) ** 2)
                mse_values.append(mse)
                
                # Calculate PSNR
                if mse > 0:
                    psnr = 20 * np.log10(255.0 / np.sqrt(mse))
                    psnr_values.append(psnr)
                
                frame_count += 1
                
                # Limit comparison to first 100 frames for performance
                if frame_count >= 100:
                    break
                    
        finally:
            cap1.release()
            cap2.release()
        
        if not psnr_values:
            return {"error": "No valid frames for comparison"}
        
        return {
            "average_psnr": np.mean(psnr_values),
            "average_mse": np.mean(mse_values),
            "min_psnr": np.min(psnr_values),
            "max_psnr": np.max(psnr_values),
            "frames_compared": frame_count
        }