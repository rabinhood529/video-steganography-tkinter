#!/usr/bin/env python3
"""
Video Steganography Tool - Main Entry Point

A comprehensive Python application for hiding and extracting secret files 
within video files using steganography techniques.

Author: AI Assistant
Version: 1.0
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from gui.main_window import MainWindow
    from utils.logger import setup_logger
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)


def check_dependencies():
    """Check if all required dependencies are available."""
    required_modules = [
        'cv2', 'numpy', 'PIL', 'cryptography', 'scipy', 'docx'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            if module == 'PIL':
                import PIL
            elif module == 'docx':
                import docx
            else:
                __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        error_msg = f"Missing required modules: {', '.join(missing_modules)}\n\n"
        error_msg += "Please install them using:\n"
        error_msg += "pip install -r requirements.txt"
        
        # Try to show GUI error if tkinter is available
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Missing Dependencies", error_msg)
            root.destroy()
        except:
            print(error_msg)
        
        return False
    
    return True


def create_directories():
    """Create necessary directories if they don't exist."""
    directories = ['logs', 'temp', 'output']
    
    for directory in directories:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
            except OSError as e:
                print(f"Warning: Could not create directory '{directory}': {e}")


def main():
    """Main application entry point."""
    print("=" * 60)
    print("Video Steganography Tool v1.0")
    print("=" * 60)
    
    # Check dependencies
    print("Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    print("✓ All dependencies found")
    
    # Create necessary directories
    print("Setting up directories...")
    create_directories()
    print("✓ Directories ready")
    
    # Setup logging
    print("Initializing logging...")
    logger = setup_logger()
    logger.info("Video Steganography Tool starting up")
    print("✓ Logging initialized")
    
    # Check Python version
    if sys.version_info < (3, 8):
        error_msg = f"Python 3.8+ required. Current version: {sys.version}"
        logger.error(error_msg)
        print(f"Error: {error_msg}")
        sys.exit(1)
    
    print(f"✓ Python version: {sys.version.split()[0]}")
    
    try:
        print("Launching GUI...")
        logger.info("Starting GUI application")
        
        # Create and run main window
        app = MainWindow()
        app.run()
        
        logger.info("Application closed normally")
        print("Application closed.")
        
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        print("\nApplication interrupted by user.")
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"Error: {e}")
        
        # Show error dialog if possible
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Application Error", 
                               f"An unexpected error occurred:\n\n{str(e)}\n\n"
                               f"Check the log files in the 'logs' directory for more details.")
            root.destroy()
        except:
            pass
        
        sys.exit(1)


if __name__ == "__main__":
    main()