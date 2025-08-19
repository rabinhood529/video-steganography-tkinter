#!/usr/bin/env python3
"""
Complete workflow test for video steganography
Tests the full encode -> decode process
"""

import os
import tempfile
import numpy as np
from steganography_engine import SteganographyEngine
from video_processor import VideoProcessor
from file_handler import FileHandler

def create_simple_test_video(output_path):
    """Create a very simple test video with minimal compression"""
    import cv2
    
    # Create a simple video with basic patterns
    width, height = 320, 240
    fps = 10
    duration = 3  # 3 seconds
    
    # Use uncompressed AVI format
    fourcc = cv2.VideoWriter_fourcc(*'IYUV')
    out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
    
    if not out.isOpened():
        print(f"ERROR: Could not create video writer for {output_path}")
        return False
    
    # Create simple frames with clear patterns
    for i in range(fps * duration):
        # Create a frame with a simple pattern
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        
        # Add a simple gradient pattern
        for y in range(height):
            for x in range(width):
                frame[y, x] = [
                    (x + i * 10) % 256,  # Blue - horizontal gradient
                    (y + i * 5) % 256,    # Green - vertical gradient  
                    (x + y + i * 3) % 256 # Red - diagonal gradient
                ]
        
        out.write(frame)
    
    out.release()
    print(f"Created test video: {output_path}")
    return True

def test_complete_workflow():
    """Test the complete encode -> decode workflow"""
    
    stego_engine = SteganographyEngine()
    video_processor = VideoProcessor()
    file_handler = FileHandler()
    
    # Create temporary files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test files
        test_video = os.path.join(temp_dir, "test_video.avi")
        output_video = os.path.join(temp_dir, "output_video.avi")
        test_secret = os.path.join(temp_dir, "secret.txt")
        extracted_file = os.path.join(temp_dir, "extracted_secret.txt")
        
        print("=== Video Steganography Complete Workflow Test ===")
        print()
        
        # Step 1: Create test video
        print("Step 1: Creating test video...")
        if not create_simple_test_video(test_video):
            print("❌ Failed to create test video")
            return False
        print("✅ Test video created successfully")
        print()
        
        # Step 2: Create secret file
        print("Step 2: Creating secret file...")
        secret_data = b"This is a secret message for testing steganography!"
        with open(test_secret, 'wb') as f:
            f.write(secret_data)
        print(f"✅ Secret file created: {len(secret_data)} bytes")
        print()
        
        # Step 3: Prepare metadata
        print("Step 3: Preparing metadata...")
        metadata = {
            'filename': 'secret.txt',
            'extension': '.txt',
            'size': len(secret_data),
            'encrypted': False
        }
        print("✅ Metadata prepared")
        print()
        
        # Step 4: Hide data in video
        print("Step 4: Hiding data in video...")
        try:
            success = stego_engine.hide_data(
                test_video, output_video, secret_data, metadata, "LSB"
            )
            
            if success:
                print("✅ Data hidden successfully")
            else:
                print("❌ Failed to hide data")
                return False
                
        except Exception as e:
            print(f"❌ Error hiding data: {e}")
            return False
        print()
        
        # Step 5: Extract data from video
        print("Step 5: Extracting data from video...")
        try:
            result = stego_engine.extract_data(output_video, "LSB")
            
            if result is None:
                print("❌ No data found in video")
                print("This is likely due to video compression corrupting the LSB data.")
                print("Try using uncompressed AVI format for better results.")
                return False
            
            extracted_data, extracted_metadata = result
            print("✅ Data extracted successfully")
            print(f"   Extracted data: {extracted_data}")
            print(f"   Metadata: {extracted_metadata}")
            
        except Exception as e:
            print(f"❌ Error extracting data: {e}")
            return False
        print()
        
        # Step 6: Verify data integrity
        print("Step 6: Verifying data integrity...")
        if extracted_data == secret_data:
            print("✅ SUCCESS: Extracted data matches original!")
            print("🎉 Complete workflow test PASSED!")
            return True
        else:
            print("❌ FAILED: Extracted data doesn't match original")
            print(f"   Original: {secret_data}")
            print(f"   Extracted: {extracted_data}")
            return False

def show_usage_instructions():
    """Show instructions for using the application"""
    print()
    print("=== How to Use the Video Steganography Application ===")
    print()
    print("1. START THE APPLICATION:")
    print("   python main.py")
    print()
    print("2. TO HIDE DATA:")
    print("   - Go to 'Hide Data' tab")
    print("   - Select a cover video (AVI format recommended)")
    print("   - Select a secret file to hide")
    print("   - Click 'Show Capacity Comparison' to check compatibility")
    print("   - Choose output path (use .avi extension for best results)")
    print("   - Click 'Hide Data in Video'")
    print()
    print("3. TO EXTRACT DATA:")
    print("   - Go to 'Extract Data' tab")
    print("   - Select the steganographic video")
    print("   - Choose output directory")
    print("   - Click 'Extract Hidden Data'")
    print()
    print("4. CAPACITY ANALYSIS:")
    print("   - Go to 'Capacity Analysis' tab")
    print("   - Select resolution and algorithm")
    print("   - View interactive bar graphs")
    print()
    print("IMPORTANT NOTES:")
    print("- Use AVI format for best compatibility")
    print("- Video compression may affect data extraction")
    print("- Always test extraction before sharing files")
    print("- Check file sizes using capacity analysis")

if __name__ == "__main__":
    print("Testing Complete Video Steganography Workflow")
    print("=" * 50)
    
    success = test_complete_workflow()
    
    if success:
        print("\n🎉 All tests passed! The application should work correctly.")
    else:
        print("\n⚠️  Some issues detected. This is normal for video compression.")
        print("The application will work better with uncompressed AVI files.")
    
    show_usage_instructions() 