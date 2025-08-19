#!/usr/bin/env python3
"""
Simple extraction test to verify the steganography works
"""

import cv2
import numpy as np
from steganography_engine import SteganographyEngine

def create_simple_test_video():
    """Create a very simple test video"""
    width, height = 320, 240
    fps = 5
    duration = 3  # 3 seconds
    
    # Use uncompressed AVI with minimal processing
    fourcc = cv2.VideoWriter_fourcc(*'IYUV')
    out = cv2.VideoWriter('simple_test.avi', fourcc, fps, (width, height))
    
    # Create very simple frames with solid colors
    for i in range(fps * duration):
        # Create a simple frame with a solid color
        frame = np.full((height, width, 3), 128, dtype=np.uint8)
        
        # Add some variation to make it more realistic
        frame[:, :, 0] = 128 + (i % 64)  # Blue channel
        frame[:, :, 1] = 128 + ((i + 10) % 64)  # Green channel  
        frame[:, :, 2] = 128 + ((i + 20) % 64)  # Red channel
        
        out.write(frame)
    
    out.release()
    print("✅ Created simple test video: simple_test.avi")
    return 'simple_test.avi'

def test_simple_hide_and_extract():
    """Test hiding and extracting with simple video"""
    print("=== Simple Hide and Extract Test ===")
    
    stego_engine = SteganographyEngine()
    
    # Create test video
    test_video = create_simple_test_video()
    
    # Simple test data
    secret_data = b"Hello World! This is a test."
    
    # Test metadata
    metadata = {
        'filename': 'test.txt',
        'extension': '.txt',
        'size': len(secret_data),
        'encrypted': False
    }
    
    print(f"Secret data: {secret_data}")
    print(f"Data size: {len(secret_data)} bytes")
    
    # Test encoding
    print("\nTesting encoding...")
    try:
        success = stego_engine.hide_data(
            test_video, 'simple_output.avi', secret_data, metadata, "LSB"
        )
        
        if success:
            print("✅ Encoding successful")
        else:
            print("❌ Encoding failed")
            return False
            
    except Exception as e:
        print(f"❌ Encoding error: {e}")
        return False
    
    # Test extraction
    print("\nTesting extraction...")
    try:
        result = stego_engine.extract_data('simple_output.avi', "LSB")
        
        if result is None:
            print("❌ No data extracted")
            return False
        
        extracted_data, extracted_metadata = result
        print(f"✅ Data extracted: {extracted_data}")
        print(f"✅ Metadata: {extracted_metadata}")
        
        if extracted_data == secret_data:
            print("🎉 SUCCESS: Simple test works!")
            return True
        else:
            print(f"⚠️  Data mismatch:")
            print(f"   Original: {secret_data}")
            print(f"   Extracted: {extracted_data}")
            return False
            
    except Exception as e:
        print(f"❌ Extraction error: {e}")
        return False

def test_direct_frame_manipulation():
    """Test direct frame manipulation without video compression"""
    print("\n=== Direct Frame Manipulation Test ===")
    
    # Create a simple frame
    frame = np.full((100, 100, 3), 128, dtype=np.uint8)
    
    # Test data
    test_data = b"TEST"
    binary_data = ''.join(format(byte, '08b') for byte in test_data)
    
    print(f"Original frame shape: {frame.shape}")
    print(f"Test data: {test_data}")
    print(f"Binary data: {binary_data}")
    
    # Hide data directly in frame
    stego_engine = SteganographyEngine()
    modified_frame = stego_engine._hide_bits_in_frame_lsb(frame, binary_data, 0)
    
    # Extract data from modified frame
    extracted_bits = stego_engine._extract_bits_from_frame_lsb(modified_frame)
    extracted_bits = extracted_bits[:len(binary_data)]  # Take only what we hid
    
    print(f"Extracted bits: {extracted_bits}")
    
    # Convert back to bytes
    extracted_bytes = stego_engine._binary_to_bytes(extracted_bits)
    print(f"Extracted bytes: {extracted_bytes}")
    
    if extracted_bytes == test_data:
        print("✅ Direct frame manipulation works!")
        return True
    else:
        print("❌ Direct frame manipulation failed")
        return False

if __name__ == "__main__":
    print("Simple Extraction Test")
    print("=" * 40)
    
    # Test direct frame manipulation first
    frame_success = test_direct_frame_manipulation()
    
    # Test simple video
    video_success = test_simple_hide_and_extract()
    
    if frame_success and video_success:
        print("\n🎉 All tests passed!")
    else:
        print("\n⚠️  Some tests failed")
        print("This helps identify where the issue is occurring") 