#!/usr/bin/env python3
"""
Simple test for LSB steganography without video compression
"""

import numpy as np
from steganography_engine import SteganographyEngine

def test_lsb_direct():
    """Test LSB encoding/decoding directly on numpy arrays"""
    
    stego_engine = SteganographyEngine()
    
    # Create a simple test frame
    frame = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    
    # Test data
    secret_data = b"Hello World!"
    metadata = {
        'filename': 'test.txt',
        'extension': '.txt',
        'size': len(secret_data),
        'encrypted': False
    }
    
    # Prepare payload
    payload = stego_engine._prepare_payload(secret_data, metadata)
    print(f"Original payload: {payload}")
    
    # Convert to binary
    binary_data = ''.join(format(byte, '08b') for byte in payload)
    print(f"Binary data length: {len(binary_data)} bits")
    
    # Hide in frame
    modified_frame = stego_engine._hide_bits_in_frame_lsb(frame, binary_data, 0)
    print(f"Frame modified: {frame.shape}")
    
    # Extract from frame - only the bits we actually hid
    extracted_bits = stego_engine._extract_bits_from_frame_lsb(modified_frame)
    # Only take the first 904 bits (the ones we actually hid)
    extracted_bits = extracted_bits[:len(binary_data)]
    print(f"Extracted bits length: {len(extracted_bits)}")
    
    # Convert back to bytes
    extracted_bytes = stego_engine._binary_to_bytes(extracted_bits)
    print(f"Extracted bytes: {extracted_bytes}")
    
    # Parse payload
    try:
        extracted_data, extracted_metadata = stego_engine._parse_payload(extracted_bytes)
        print(f"Extracted data: {extracted_data}")
        print(f"Extracted metadata: {extracted_metadata}")
        
        if extracted_data == secret_data:
            print("✓ SUCCESS: Data matches!")
            return True
        else:
            print("✗ FAILED: Data doesn't match!")
            return False
            
    except Exception as e:
        print(f"✗ FAILED: Error parsing payload: {e}")
        return False

if __name__ == "__main__":
    print("Testing Direct LSB Steganography")
    print("=" * 40)
    
    success = test_lsb_direct()
    
    if success:
        print("\n🎉 Direct LSB test passed!")
    else:
        print("\n❌ Direct LSB test failed!") 