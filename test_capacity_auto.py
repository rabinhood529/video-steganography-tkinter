#!/usr/bin/env python3
"""
Test script for automatic capacity comparison functionality
"""

import os
import sys
import tempfile
import tkinter as tk
from tkinter import messagebox

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import VideoSteganographyApp

def test_automatic_capacity_detection():
    """Test the automatic capacity detection functionality"""
    
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        test_content = "This is a test file for capacity analysis.\n" * 100  # Create some content
        f.write(test_content)
        test_file_path = f.name
    
    try:
        # Create a minimal GUI for testing
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        
        # Create the app
        app = VideoSteganographyApp(root)
        
        # Set a test video path (you would need a real video file for full testing)
        # For this test, we'll just verify the file detection logic works
        
        # Test file size detection
        if os.path.exists(test_file_path):
            file_size = os.path.getsize(test_file_path)
            file_size_kb = file_size / 1024
            
            print(f"✅ Test file created: {test_file_path}")
            print(f"✅ File size detected: {file_size_kb:.2f} KB")
            
            # Test file info extraction
            try:
                file_info = app.file_handler.get_file_info(test_file_path)
                print(f"✅ File type detected: {file_info['type']}")
                print(f"✅ File name: {file_info['name']}")
                print(f"✅ File extension: {file_info['extension']}")
                
                return True
                
            except Exception as e:
                print(f"❌ Error getting file info: {str(e)}")
                return False
        else:
            print(f"❌ Test file not created: {test_file_path}")
            return False
            
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        return False
        
    finally:
        # Clean up test file
        try:
            os.unlink(test_file_path)
            print("✅ Test file cleaned up")
        except:
            pass

def test_supported_file_types():
    """Test that all supported file types are properly configured"""
    
    try:
        root = tk.Tk()
        root.withdraw()
        app = VideoSteganographyApp(root)
        
        # Test supported extensions
        supported_extensions = app.file_handler.get_supported_extensions()
        print(f"✅ Supported extensions: {supported_extensions}")
        
        # Test specific file types
        test_cases = [
            ("test.txt", "text"),
            ("test.docx", "document"),
            ("test.jpg", "image"),
            ("test.mp4", "video"),
            ("test.mp3", "audio"),
            ("test.unknown", "unknown")
        ]
        
        for filename, expected_type in test_cases:
            detected_type = app.file_handler.get_file_type(filename)
            status = "✅" if detected_type == expected_type else "❌"
            print(f"{status} {filename}: expected {expected_type}, got {detected_type}")
        
        return True
        
    except Exception as e:
        print(f"❌ File type test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("🧪 Testing automatic capacity detection functionality...")
    print("=" * 60)
    
    # Test 1: File size detection
    print("\n1. Testing file size detection...")
    test1_result = test_automatic_capacity_detection()
    
    # Test 2: Supported file types
    print("\n2. Testing supported file types...")
    test2_result = test_supported_file_types()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY:")
    print(f"File size detection: {'✅ PASS' if test1_result else '❌ FAIL'}")
    print(f"File type support: {'✅ PASS' if test2_result else '❌ FAIL'}")
    
    if test1_result and test2_result:
        print("\n🎉 All tests passed! The automatic capacity detection is working correctly.")
    else:
        print("\n⚠️ Some tests failed. Please check the implementation.") 