#!/usr/bin/env python3
"""
Test the backup method for reliable extraction
"""

import cv2
import numpy as np
from steganography_engine import SteganographyEngine

def test_backup_method():
    """Test the backup hiding and extraction method"""
    print("=== Testing Backup Method ===")
    
    stego_engine = SteganographyEngine()
    
    # Create a simple test video
    width, height = 320, 240
    fps = 5
    duration = 3
    
    fourcc = cv2.VideoWriter_fourcc(*'IYUV')
    out = cv2.VideoWriter('backup_test.avi', fourcc, fps, (width, height))
    
    for i in range(fps * duration):
        frame = np.full((height, width, 3), 128, dtype=np.uint8)
        frame[:, :, 0] = 128 + (i % 64)
        frame[:, :, 1] = 128 + ((i + 10) % 64)
        frame[:, :, 2] = 128 + ((i + 20) % 64)
        out.write(frame)
    
    out.release()
    print("✅ Created test video: backup_test.avi")
    
    # Test data
    secret_data = b"This is a test message for the backup method!"
    
    # Test metadata
    metadata = {
        'filename': 'backup_test.txt',
        'extension': '.txt',
        'size': len(secret_data),
        'encrypted': False
    }
    
    print(f"Secret data: {secret_data}")
    print(f"Data size: {len(secret_data)} bytes")
    
    # Test encoding with backup
    print("\nTesting encoding with backup...")
    try:
        success = stego_engine.hide_data_with_backup(
            'backup_test.avi', 'backup_output.avi', secret_data, metadata, "LSB"
        )
        
        if success:
            print("✅ Encoding with backup successful")
        else:
            print("❌ Encoding with backup failed")
            return False
            
    except Exception as e:
        print(f"❌ Encoding error: {e}")
        return False
    
    # Test extraction with backup
    print("\nTesting extraction with backup...")
    try:
        result = stego_engine.extract_data_with_backup('backup_output.avi', "LSB")
        
        if result is None:
            print("❌ No data extracted with backup")
            return False
        
        extracted_data, extracted_metadata = result
        print(f"✅ Data extracted: {extracted_data}")
        print(f"✅ Metadata: {extracted_metadata}")
        
        if extracted_data == secret_data:
            print("🎉 SUCCESS: Backup method works perfectly!")
            return True
        else:
            print(f"⚠️  Data mismatch:")
            print(f"   Original: {secret_data}")
            print(f"   Extracted: {extracted_data}")
            return False
            
    except Exception as e:
        print(f"❌ Extraction error: {e}")
        return False

if __name__ == "__main__":
    print("Backup Method Test")
    print("=" * 30)
    
    success = test_backup_method()
    
    if success:
        print("\n🎉 Backup method is working correctly!")
        print("This should solve the extraction issues!")
    else:
        print("\n❌ Backup method failed")
        print("Need to investigate further") 