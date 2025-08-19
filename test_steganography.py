#!/usr/bin/env python3
"""
Test script for steganography engine fixes
Tests encoding and decoding functionality
"""

import os
import tempfile
import numpy as np
from steganography_engine import SteganographyEngine
from video_processor import VideoProcessor
from file_handler import FileHandler

def create_test_video(output_path, width=640, height=480, frames=30):
    """Create a simple test video"""
    import cv2
    
    # Create video writer
    fourcc = cv2.VideoWriter_fourcc(*'IYUV')  # Uncompressed AVI
    out = cv2.VideoWriter(output_path, fourcc, 30.0, (width, height))
    
    # Create test frames
    for i in range(frames):
        # Create a frame with some pattern
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Add some color variation
        frame[:, :, 0] = (i * 10) % 256  # Blue channel
        frame[:, :, 1] = (i * 15) % 256  # Green channel  
        frame[:, :, 2] = (i * 20) % 256  # Red channel
        
        # Add some patterns
        frame[::20, ::20] = [255, 255, 255]  # White dots
        
        out.write(frame)
    
    out.release()
    print(f"Created test video: {output_path}")

def test_steganography():
    """Test the steganography engine"""
    
    # Initialize components
    stego_engine = SteganographyEngine()
    video_processor = VideoProcessor()
    file_handler = FileHandler()
    
    # Create temporary files
    with tempfile.TemporaryDirectory() as temp_dir:
        test_video = os.path.join(temp_dir, "test_video.avi")
        output_video = os.path.join(temp_dir, "output_video.avi")
        test_file = os.path.join(temp_dir, "test_secret.txt")
        extracted_file = os.path.join(temp_dir, "extracted_secret.txt")
        
        # Create test video
        print("Creating test video...")
        create_test_video(test_video, width=320, height=240, frames=10)
        
        # Create test secret file
        print("Creating test secret file...")
        secret_data = b"This is a test secret message for steganography testing!"
        with open(test_file, 'wb') as f:
            f.write(secret_data)
        
        # Test metadata
        metadata = {
            'filename': 'test_secret.txt',
            'extension': '.txt',
            'size': len(secret_data),
            'encrypted': False
        }
        
        print(f"Original secret data: {secret_data}")
        print(f"Secret data size: {len(secret_data)} bytes")
        
        # Test encoding
        print("\nTesting encoding...")
        try:
            success = stego_engine.hide_data(
                test_video, output_video, secret_data, metadata, "LSB"
            )
            
            if success:
                print("✓ Encoding successful")
            else:
                print("✗ Encoding failed")
                return False
                
        except Exception as e:
            print(f"✗ Encoding error: {e}")
            return False
        
        # Test decoding
        print("\nTesting decoding...")
        try:
            result = stego_engine.extract_data(output_video, "LSB")
            
            if result is None:
                print("✗ No data extracted")
                return False
            
            extracted_data, extracted_metadata = result
            print(f"✓ Extracted data: {extracted_data}")
            print(f"✓ Extracted metadata: {extracted_metadata}")
            
            # Verify data integrity
            if extracted_data == secret_data:
                print("✓ Data integrity verified - extracted data matches original")
                return True
            else:
                print("✗ Data integrity failed - extracted data doesn't match original")
                print(f"Original: {secret_data}")
                print(f"Extracted: {extracted_data}")
                return False
                
        except Exception as e:
            print(f"✗ Decoding error: {e}")
            return False

if __name__ == "__main__":
    print("Testing Steganography Engine Fixes")
    print("=" * 40)
    
    success = test_steganography()
    
    if success:
        print("\n🎉 All tests passed! Steganography engine is working correctly.")
    else:
        print("\n❌ Tests failed. There are still issues with the steganography engine.") 