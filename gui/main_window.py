"""
Main GUI window for video steganography application.
"""

import tkinter as tk
from tkinter import ttk
import threading
from typing import Optional

from core.steganography import VideoSteganography
from core.video_processor import VideoProcessor
from utils.file_handler import FileHandler
from utils.logger import get_logger
from gui.components import (
    FileInfoFrame, VideoInfoFrame, CapacityFrame, LogFrame,
    ProgressDialog, PasswordDialog, show_error, show_info, 
    show_warning, ask_yes_no, select_file, select_save_file
)

logger = get_logger(__name__)


class MainWindow:
    """Main application window."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Video Steganography Tool")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Initialize components
        self.steganography = VideoSteganography()
        self.video_processor = VideoProcessor()
        
        # File paths
        self.cover_video_path = None
        self.secret_file_path = None
        self.stego_video_path = None
        
        # GUI components
        self.log_frame = None
        self.video_info_frame = None
        self.secret_info_frame = None
        self.capacity_frame = None
        
        # Setup GUI
        self._create_widgets()
        self._setup_logging()
        
        # Center window
        self._center_window()
        
        logger.info("Video Steganography Tool initialized")
    
    def _create_widgets(self):
        """Create main window widgets."""
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self._create_embed_tab()
        self._create_extract_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _create_embed_tab(self):
        """Create embedding tab."""
        embed_frame = ttk.Frame(self.notebook)
        self.notebook.add(embed_frame, text="Embed File")
        
        # Main container with paned window
        paned = ttk.PanedWindow(embed_frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top frame for file selection and info
        top_frame = ttk.Frame(paned)
        paned.add(top_frame, weight=3)
        
        # File selection frame
        file_frame = ttk.LabelFrame(top_frame, text="File Selection", padding="10")
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Cover video selection
        cover_frame = ttk.Frame(file_frame)
        cover_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(cover_frame, text="Select Cover Video", 
                  command=self._select_cover_video, width=20).pack(side=tk.LEFT)
        
        self.cover_video_var = tk.StringVar(value="No video selected")
        ttk.Label(cover_frame, textvariable=self.cover_video_var, 
                 foreground="blue").pack(side=tk.LEFT, padx=(10, 0))
        
        # Secret file selection
        secret_frame = ttk.Frame(file_frame)
        secret_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(secret_frame, text="Select Secret File", 
                  command=self._select_secret_file, width=20).pack(side=tk.LEFT)
        
        self.secret_file_var = tk.StringVar(value="No file selected")
        ttk.Label(secret_frame, textvariable=self.secret_file_var, 
                 foreground="blue").pack(side=tk.LEFT, padx=(10, 0))
        
        # Calculate capacity button
        ttk.Button(file_frame, text="Calculate Capacity", 
                  command=self._calculate_capacity).pack(pady=(10, 0))
        
        # Information frames container
        info_container = ttk.Frame(top_frame)
        info_container.pack(fill=tk.BOTH, expand=True)
        
        # Left column - Video info and capacity
        left_column = ttk.Frame(info_container)
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        self.video_info_frame = VideoInfoFrame(left_column, "Cover Video Information")
        self.video_info_frame.frame.pack(fill=tk.X, pady=(0, 10))
        
        self.capacity_frame = CapacityFrame(left_column)
        self.capacity_frame.frame.pack(fill=tk.X)
        
        # Right column - Secret file info
        right_column = ttk.Frame(info_container)
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.secret_info_frame = FileInfoFrame(right_column, "Secret File Information")
        self.secret_info_frame.frame.pack(fill=tk.X, pady=(0, 10))
        
        # Embedding options
        options_frame = ttk.LabelFrame(right_column, text="Embedding Options", padding="10")
        options_frame.pack(fill=tk.X)
        
        # Algorithm selection
        ttk.Label(options_frame, text="Algorithm:").pack(anchor=tk.W)
        self.algorithm_var = tk.StringVar(value="LSB")
        algorithm_frame = ttk.Frame(options_frame)
        algorithm_frame.pack(fill=tk.X, pady=(5, 10))
        
        ttk.Radiobutton(algorithm_frame, text="LSB", variable=self.algorithm_var, 
                       value="LSB").pack(side=tk.LEFT)
        ttk.Radiobutton(algorithm_frame, text="DCT", variable=self.algorithm_var, 
                       value="DCT").pack(side=tk.LEFT, padx=(20, 0))
        
        # Password option
        self.use_password_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Use password encryption", 
                       variable=self.use_password_var).pack(anchor=tk.W, pady=(0, 10))
        
        # Embed button
        self.embed_btn = ttk.Button(options_frame, text="Embed File", 
                                   command=self._embed_file, state=tk.DISABLED)
        self.embed_btn.pack(pady=(10, 0))
        
        # Bottom frame for log
        bottom_frame = ttk.Frame(paned)
        paned.add(bottom_frame, weight=1)
        
        self.log_frame = LogFrame(bottom_frame)
        self.log_frame.frame.pack(fill=tk.BOTH, expand=True)
    
    def _create_extract_tab(self):
        """Create extraction tab."""
        extract_frame = ttk.Frame(self.notebook)
        self.notebook.add(extract_frame, text="Extract File")
        
        # Main container
        main_container = ttk.Frame(extract_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # File selection
        file_frame = ttk.LabelFrame(main_container, text="File Selection", padding="10")
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Stego video selection
        stego_frame = ttk.Frame(file_frame)
        stego_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(stego_frame, text="Select Stego Video", 
                  command=self._select_stego_video, width=20).pack(side=tk.LEFT)
        
        self.stego_video_var = tk.StringVar(value="No video selected")
        ttk.Label(stego_frame, textvariable=self.stego_video_var, 
                 foreground="blue").pack(side=tk.LEFT, padx=(10, 0))
        
        # Extraction options
        options_frame = ttk.LabelFrame(main_container, text="Extraction Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Algorithm selection
        ttk.Label(options_frame, text="Algorithm used for embedding:").pack(anchor=tk.W)
        self.extract_algorithm_var = tk.StringVar(value="LSB")
        extract_algorithm_frame = ttk.Frame(options_frame)
        extract_algorithm_frame.pack(fill=tk.X, pady=(5, 10))
        
        ttk.Radiobutton(extract_algorithm_frame, text="LSB", 
                       variable=self.extract_algorithm_var, value="LSB").pack(side=tk.LEFT)
        ttk.Radiobutton(extract_algorithm_frame, text="DCT", 
                       variable=self.extract_algorithm_var, value="DCT").pack(side=tk.LEFT, padx=(20, 0))
        
        # Password option
        self.extract_use_password_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="File was encrypted with password", 
                       variable=self.extract_use_password_var).pack(anchor=tk.W, pady=(0, 10))
        
        # Extract button
        self.extract_btn = ttk.Button(options_frame, text="Extract File", 
                                     command=self._extract_file, state=tk.DISABLED)
        self.extract_btn.pack(pady=(10, 0))
        
        # Stego video info
        self.stego_info_frame = VideoInfoFrame(main_container, "Stego Video Information")
        self.stego_info_frame.frame.pack(fill=tk.X, pady=(0, 10))
        
        # Log frame for extraction tab
        self.extract_log_frame = LogFrame(main_container)
        self.extract_log_frame.frame.pack(fill=tk.BOTH, expand=True)
    
    def _center_window(self):
        """Center the window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def _setup_logging(self):
        """Setup logging to GUI."""
        # Custom handler to send logs to GUI
        class GUILogHandler:
            def __init__(self, log_frame):
                self.log_frame = log_frame
            
            def emit(self, record):
                if hasattr(record, 'levelname'):
                    level = record.levelname
                    message = record.getMessage()
                    self.log_frame.add_log(message, level)
        
        # Add GUI handler to logger
        gui_handler = GUILogHandler(self.log_frame)
        logger.addHandler = lambda handler: None  # Prevent duplicate handlers
    
    def _select_cover_video(self):
        """Select cover video file."""
        filetypes = [
            ("Video files", "*.mp4 *.avi"),
            ("MP4 files", "*.mp4"),
            ("AVI files", "*.avi"),
            ("All files", "*.*")
        ]
        
        file_path = select_file(self.root, "Select Cover Video", filetypes)
        if file_path:
            # Validate video
            is_valid, error = FileHandler.validate_cover_video(file_path)
            if not is_valid:
                show_error(self.root, "Invalid Video", error)
                return
            
            self.cover_video_path = file_path
            self.cover_video_var.set(file_path)
            
            # Update video info
            self._update_video_info()
            self._update_embed_button_state()
            
            self.log_frame.add_log(f"Cover video selected: {file_path}", "INFO")
    
    def _select_secret_file(self):
        """Select secret file to embed."""
        filetypes = [
            ("Text files", "*.txt"),
            ("Word documents", "*.doc *.docx"),
            ("Image files", "*.jpg *.jpeg *.png"),
            ("Video files", "*.mp4 *.avi"),
            ("All supported", "*.txt *.doc *.docx *.jpg *.jpeg *.png *.mp4 *.avi"),
            ("All files", "*.*")
        ]
        
        file_path = select_file(self.root, "Select Secret File", filetypes)
        if file_path:
            # Validate secret file
            is_valid, error = FileHandler.validate_secret_file(file_path)
            if not is_valid:
                show_error(self.root, "Invalid File", error)
                return
            
            self.secret_file_path = file_path
            self.secret_file_var.set(file_path)
            
            # Update secret file info
            self._update_secret_file_info()
            self._update_embed_button_state()
            
            self.log_frame.add_log(f"Secret file selected: {file_path}", "INFO")
    
    def _select_stego_video(self):
        """Select stego video for extraction."""
        filetypes = [
            ("Video files", "*.mp4 *.avi"),
            ("MP4 files", "*.mp4"),
            ("AVI files", "*.avi"),
            ("All files", "*.*")
        ]
        
        file_path = select_file(self.root, "Select Stego Video", filetypes)
        if file_path:
            # Validate video
            is_valid, error = FileHandler.validate_cover_video(file_path)
            if not is_valid:
                show_error(self.root, "Invalid Video", error)
                return
            
            self.stego_video_path = file_path
            self.stego_video_var.set(file_path)
            
            # Update stego video info
            self._update_stego_video_info()
            self._update_extract_button_state()
            
            self.extract_log_frame.add_log(f"Stego video selected: {file_path}", "INFO")
    
    def _update_video_info(self):
        """Update cover video information display."""
        if not self.cover_video_path:
            return
        
        try:
            # Get video properties
            properties = self.video_processor.get_video_properties(self.cover_video_path)
            if properties:
                file_size = FileHandler.get_file_size(self.cover_video_path)
                
                info = {
                    'path': self.cover_video_path,
                    'size': FileHandler.format_file_size(file_size),
                    'format': FileHandler.get_file_extension(self.cover_video_path).upper(),
                    'resolution': f"{properties['width']}x{properties['height']} ({properties['resolution_category']})",
                    'duration': f"{properties['duration']:.2f} seconds",
                    'fps': f"{properties['fps']:.2f}"
                }
                
                self.video_info_frame.update_info(info)
                
        except Exception as e:
            logger.error(f"Error updating video info: {e}")
    
    def _update_secret_file_info(self):
        """Update secret file information display."""
        if not self.secret_file_path:
            return
        
        try:
            file_size = FileHandler.get_file_size(self.secret_file_path)
            
            info = {
                'path': self.secret_file_path,
                'size': FileHandler.format_file_size(file_size),
                'format': FileHandler.get_file_extension(self.secret_file_path).upper()
            }
            
            self.secret_info_frame.update_info(info)
            
        except Exception as e:
            logger.error(f"Error updating secret file info: {e}")
    
    def _update_stego_video_info(self):
        """Update stego video information display."""
        if not self.stego_video_path:
            return
        
        try:
            properties = self.video_processor.get_video_properties(self.stego_video_path)
            if properties:
                file_size = FileHandler.get_file_size(self.stego_video_path)
                
                info = {
                    'path': self.stego_video_path,
                    'size': FileHandler.format_file_size(file_size),
                    'format': FileHandler.get_file_extension(self.stego_video_path).upper(),
                    'resolution': f"{properties['width']}x{properties['height']} ({properties['resolution_category']})",
                    'duration': f"{properties['duration']:.2f} seconds",
                    'fps': f"{properties['fps']:.2f}"
                }
                
                self.stego_info_frame.update_info(info)
                
        except Exception as e:
            logger.error(f"Error updating stego video info: {e}")
    
    def _calculate_capacity(self):
        """Calculate and display embedding capacity."""
        if not self.cover_video_path:
            show_warning(self.root, "No Video", "Please select a cover video first.")
            return
        
        try:
            self.status_var.set("Calculating capacity...")
            self.root.update()
            
            # Get capacity info
            capacity_info = self.video_processor.get_capacity_info(self.cover_video_path)
            
            if capacity_info:
                lsb_capacity = capacity_info['lsb_capacity_formatted']
                dct_capacity = capacity_info['dct_capacity_formatted']
                
                self.capacity_frame.update_capacity(lsb_capacity, dct_capacity)
                self.capacity_frame.clear_warning()
                
                # Check if secret file exceeds capacity
                if self.secret_file_path:
                    secret_size = FileHandler.get_file_size(self.secret_file_path)
                    lsb_bytes = capacity_info['lsb_capacity_bytes']
                    dct_bytes = capacity_info['dct_capacity_bytes']
                    
                    algorithm = self.algorithm_var.get()
                    max_capacity = lsb_bytes if algorithm == "LSB" else dct_bytes
                    
                    if secret_size > max_capacity:
                        warning = f"⚠ Secret file ({FileHandler.format_file_size(secret_size)}) " \
                                f"exceeds {algorithm} capacity ({FileHandler.format_file_size(max_capacity)})"
                        self.capacity_frame.show_warning(warning)
                
                self.log_frame.add_log("Capacity calculated successfully", "SUCCESS")
            else:
                show_error(self.root, "Error", "Failed to calculate capacity")
                
        except Exception as e:
            show_error(self.root, "Error", f"Failed to calculate capacity: {str(e)}")
            logger.error(f"Capacity calculation error: {e}")
        finally:
            self.status_var.set("Ready")
    
    def _update_embed_button_state(self):
        """Update embed button state based on file selection."""
        if self.cover_video_path and self.secret_file_path:
            self.embed_btn.config(state=tk.NORMAL)
        else:
            self.embed_btn.config(state=tk.DISABLED)
    
    def _update_extract_button_state(self):
        """Update extract button state based on file selection."""
        if self.stego_video_path:
            self.extract_btn.config(state=tk.NORMAL)
        else:
            self.extract_btn.config(state=tk.DISABLED)
    
    def _embed_file(self):
        """Embed secret file into cover video."""
        if not self.cover_video_path or not self.secret_file_path:
            show_warning(self.root, "Missing Files", "Please select both cover video and secret file.")
            return
        
        # Get password if needed
        password = None
        if self.use_password_var.get():
            password_dialog = PasswordDialog(self.root, "Enter Encryption Password")
            password = password_dialog.get_password()
            if password is None:
                return  # User cancelled
            if not password.strip():
                show_warning(self.root, "Invalid Password", "Password cannot be empty.")
                return
        
        # Select output file
        filetypes = [
            ("MP4 files", "*.mp4"),
            ("AVI files", "*.avi"),
            ("All files", "*.*")
        ]
        
        output_path = select_save_file(self.root, "Save Stego Video", filetypes, ".mp4")
        if not output_path:
            return
        
        # Start embedding in separate thread
        algorithm = self.algorithm_var.get()
        
        def embed_worker():
            try:
                # Create progress dialog
                progress_dialog = ProgressDialog(self.root, "Embedding File...")
                
                def progress_callback(progress):
                    if not progress_dialog.is_cancelled():
                        progress_dialog.update_progress(progress, f"Processing... {progress}%")
                    return not progress_dialog.is_cancelled()
                
                # Perform embedding
                success, message = self.steganography.embed_file(
                    self.cover_video_path,
                    self.secret_file_path,
                    output_path,
                    algorithm,
                    password,
                    progress_callback
                )
                
                progress_dialog.close()
                
                # Show result
                if success:
                    self.log_frame.add_log(f"Embedding successful: {message}", "SUCCESS")
                    show_info(self.root, "Success", f"File embedded successfully!\n\nOutput: {output_path}")
                else:
                    self.log_frame.add_log(f"Embedding failed: {message}", "ERROR")
                    show_error(self.root, "Embedding Failed", message)
                    
            except Exception as e:
                logger.error(f"Embedding error: {e}")
                self.log_frame.add_log(f"Embedding error: {str(e)}", "ERROR")
                show_error(self.root, "Error", f"Embedding failed: {str(e)}")
        
        # Start worker thread
        thread = threading.Thread(target=embed_worker, daemon=True)
        thread.start()
    
    def _extract_file(self):
        """Extract secret file from stego video."""
        if not self.stego_video_path:
            show_warning(self.root, "No Video", "Please select a stego video first.")
            return
        
        # Get password if needed
        password = None
        if self.extract_use_password_var.get():
            password_dialog = PasswordDialog(self.root, "Enter Decryption Password")
            password = password_dialog.get_password()
            if password is None:
                return  # User cancelled
        
        # Select output location
        output_path = select_save_file(self.root, "Select Output Directory", [("All files", "*.*")])
        if not output_path:
            return
        
        # Ensure trailing slash
        if not output_path.endswith('/') and not output_path.endswith('\\'):
            output_path += '/'
        
        # Start extraction in separate thread
        algorithm = self.extract_algorithm_var.get()
        
        def extract_worker():
            try:
                # Create progress dialog
                progress_dialog = ProgressDialog(self.root, "Extracting File...")
                
                def progress_callback(progress):
                    if not progress_dialog.is_cancelled():
                        progress_dialog.update_progress(progress, f"Processing... {progress}%")
                    return not progress_dialog.is_cancelled()
                
                # Perform extraction
                success, message = self.steganography.extract_file(
                    self.stego_video_path,
                    output_path,
                    algorithm,
                    password,
                    progress_callback
                )
                
                progress_dialog.close()
                
                # Show result
                if success:
                    self.extract_log_frame.add_log(f"Extraction successful: {message}", "SUCCESS")
                    show_info(self.root, "Success", f"File extracted successfully!\n\n{message}")
                else:
                    self.extract_log_frame.add_log(f"Extraction failed: {message}", "ERROR")
                    show_error(self.root, "Extraction Failed", message)
                    
            except Exception as e:
                logger.error(f"Extraction error: {e}")
                self.extract_log_frame.add_log(f"Extraction error: {str(e)}", "ERROR")
                show_error(self.root, "Error", f"Extraction failed: {str(e)}")
        
        # Start worker thread
        thread = threading.Thread(target=extract_worker, daemon=True)
        thread.start()
    
    def run(self):
        """Start the GUI application."""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logger.info("Application interrupted by user")
        except Exception as e:
            logger.error(f"Application error: {e}")
            show_error(self.root, "Application Error", f"An unexpected error occurred: {str(e)}")
        finally:
            logger.info("Application shutting down")


if __name__ == "__main__":
    app = MainWindow()
    app.run()