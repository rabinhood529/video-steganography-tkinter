#!/usr/bin/env python3
"""
Video Steganography Tool - Main Entry Point
A comprehensive tool for embedding and extracting secret files in video files.
"""

import sys
import tkinter as tk
from tkinter import messagebox
import logging
from gui.main_window import VideoSteganographyGUI

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('video_steganography.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """Main application entry point"""
    try:
        setup_logging()
        logger = logging.getLogger(__name__)
        logger.info("Starting Video Steganography Application")
        
        root = tk.Tk()
        app = VideoSteganographyGUI(root)
        root.mainloop()
        
    except Exception as e:
        logging.error(f"Application failed to start: {e}")
        messagebox.showerror("Error", f"Failed to start application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()