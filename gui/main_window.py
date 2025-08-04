"""
Main GUI Window for Video Steganography Tool
Comprehensive Tkinter interface with all required features.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import logging
import os
from typing import Optional, Callable
import queue

from core.steganography import VideoSteganography
from utils.video_utils import VideoProcessor, VideoMetadata, FileValidator
from utils.encryption import SecureFileHandler, PasswordEncryption

logger = logging.getLogger(__name__)


class ProgressDialog:
    """Progress dialog for long-running operations"""
    
    def __init__(self, parent, title: str, message: str):
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.geometry("400x150")
        self.window.resizable(False, False)
        self.window.transient(parent)
        self.window.grab_set()
        
        # Center the dialog
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.window.winfo_screenheight() // 2) - (150 // 2)
        self.window.geometry(f"400x150+{x}+{y}")
        
        # Message label
        self.message_label = tk.Label(self.window, text=message, wraplength=350)
        self.message_label.pack(pady=10)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.window, 
            variable=self.progress_var, 
            maximum=100,
            length=350
        )
        self.progress_bar.pack(pady=10)
        
        # Status label
        self.status_label = tk.Label(self.window, text="Starting...")
        self.status_label.pack(pady=5)
        
        # Cancel button
        self.cancelled = False
        self.cancel_button = tk.Button(
            self.window, 
            text="Cancel", 
            command=self.cancel
        )
        self.cancel_button.pack(pady=5)
    
    def update_progress(self, progress: float, status: str = ""):
        """Update progress bar and status"""
        self.progress_var.set(progress)
        if status:
            self.status_label.config(text=status)
        self.window.update()
    
    def cancel(self):
        """Cancel the operation"""
        self.cancelled = True
        self.window.destroy()
    
    def close(self):
        """Close the dialog"""
        self.window.destroy()


class VideoSteganographyGUI:
    """Main GUI application class"""
    
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_variables()
        self.setup_gui()
        self.setup_logging()
        
        # Initialize components
        self.video_processor = VideoProcessor()
        self.file_validator = FileValidator()
        self.current_video_metadata: Optional[VideoMetadata] = None
        
        logger.info("GUI initialized successfully")
    
    def setup_window(self):
        """Setup main window properties"""
        self.root.title("Video Steganography Tool v1.0")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (900 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"900x700+{x}+{y}")
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
    
    def setup_variables(self):
        """Setup GUI variables"""
        self.cover_video_path = tk.StringVar()
        self.secret_file_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.method_var = tk.StringVar(value="LSB")
        self.use_password = tk.BooleanVar()
        self.password = tk.StringVar()
        self.operation_mode = tk.StringVar(value="embed")
    
    def setup_gui(self):
        """Setup the main GUI layout"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.embed_frame = ttk.Frame(self.notebook)
        self.extract_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.embed_frame, text="Embed Secret File")
        self.notebook.add(self.extract_frame, text="Extract Secret File")
        
        # Setup embed tab
        self.setup_embed_tab()
        
        # Setup extract tab
        self.setup_extract_tab()
        
        # Setup status bar
        self.setup_status_bar()
    
    def setup_embed_tab(self):
        """Setup the embed tab interface"""
        # Main container
        main_frame = ttk.Frame(self.embed_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel for file selection and settings
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Right panel for metadata and logs
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # === LEFT PANEL ===
        
        # Cover video selection
        video_group = ttk.LabelFrame(left_frame, text="Cover Video", padding=10)
        video_group.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(video_group, text="Select cover video file:").pack(anchor=tk.W)
        video_frame = ttk.Frame(video_group)
        video_frame.pack(fill=tk.X, pady=5)
        
        self.video_entry = ttk.Entry(video_frame, textvariable=self.cover_video_path, state='readonly')
        self.video_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(video_frame, text="Browse", command=self.browse_cover_video).pack(side=tk.RIGHT)
        
        # Secret file selection
        secret_group = ttk.LabelFrame(left_frame, text="Secret File", padding=10)
        secret_group.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(secret_group, text="Select secret file to hide:").pack(anchor=tk.W)
        secret_frame = ttk.Frame(secret_group)
        secret_frame.pack(fill=tk.X, pady=5)
        
        self.secret_entry = ttk.Entry(secret_frame, textvariable=self.secret_file_path, state='readonly')
        self.secret_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(secret_frame, text="Browse", command=self.browse_secret_file).pack(side=tk.RIGHT)
        
        # Output file selection
        output_group = ttk.LabelFrame(left_frame, text="Output", padding=10)
        output_group.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(output_group, text="Output video file:").pack(anchor=tk.W)
        output_frame = ttk.Frame(output_group)
        output_frame.pack(fill=tk.X, pady=5)
        
        self.output_entry = ttk.Entry(output_frame, textvariable=self.output_path)
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(output_frame, text="Browse", command=self.browse_output_file).pack(side=tk.RIGHT)
        
        # Settings
        settings_group = ttk.LabelFrame(left_frame, text="Settings", padding=10)
        settings_group.pack(fill=tk.X, pady=(0, 10))
        
        # Method selection
        ttk.Label(settings_group, text="Steganography Method:").pack(anchor=tk.W)
        method_frame = ttk.Frame(settings_group)
        method_frame.pack(fill=tk.X, pady=5)
        
        ttk.Radiobutton(method_frame, text="LSB (Faster)", variable=self.method_var, value="LSB").pack(side=tk.LEFT)
        ttk.Radiobutton(method_frame, text="DCT (More Secure)", variable=self.method_var, value="DCT").pack(side=tk.LEFT, padx=(20, 0))
        
        # Password protection
        ttk.Checkbutton(settings_group, text="Use password protection", variable=self.use_password, command=self.toggle_password).pack(anchor=tk.W, pady=5)
        
        self.password_frame = ttk.Frame(settings_group)
        self.password_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(self.password_frame, text="Password:").pack(side=tk.LEFT)
        self.password_entry = ttk.Entry(self.password_frame, textvariable=self.password, show="*", state='disabled')
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        
        # Action buttons
        button_frame = ttk.Frame(left_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.embed_button = ttk.Button(button_frame, text="Embed Secret File", command=self.embed_file, state='disabled')
        self.embed_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Clear All", command=self.clear_embed_fields).pack(side=tk.LEFT)
        
        # === RIGHT PANEL ===
        
        # Video metadata display
        metadata_group = ttk.LabelFrame(right_frame, text="Video Information", padding=10)
        metadata_group.pack(fill=tk.X, pady=(0, 10))
        
        self.metadata_text = scrolledtext.ScrolledText(metadata_group, height=8, width=40, state='disabled')
        self.metadata_text.pack(fill=tk.BOTH, expand=True)
        
        # Capacity information
        capacity_group = ttk.LabelFrame(right_frame, text="Embedding Capacity", padding=10)
        capacity_group.pack(fill=tk.X, pady=(0, 10))
        
        self.capacity_label = ttk.Label(capacity_group, text="Select a video to see capacity information")
        self.capacity_label.pack(anchor=tk.W)
        
        self.secret_size_label = ttk.Label(capacity_group, text="")
        self.secret_size_label.pack(anchor=tk.W, pady=2)
        
        self.capacity_status_label = ttk.Label(capacity_group, text="", foreground="blue")
        self.capacity_status_label.pack(anchor=tk.W, pady=2)
        
        # Log display
        log_group = ttk.LabelFrame(right_frame, text="Activity Log", padding=10)
        log_group.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_group, height=10, width=40, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_extract_tab(self):
        """Setup the extract tab interface"""
        # Main container
        main_frame = ttk.Frame(self.extract_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Right panel
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # === LEFT PANEL ===
        
        # Stego video selection
        stego_group = ttk.LabelFrame(left_frame, text="Stego Video", padding=10)
        stego_group.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(stego_group, text="Select video with hidden data:").pack(anchor=tk.W)
        stego_frame = ttk.Frame(stego_group)
        stego_frame.pack(fill=tk.X, pady=5)
        
        self.stego_video_path = tk.StringVar()
        self.stego_entry = ttk.Entry(stego_frame, textvariable=self.stego_video_path, state='readonly')
        self.stego_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(stego_frame, text="Browse", command=self.browse_stego_video).pack(side=tk.RIGHT)
        
        # Original video (for DCT)
        original_group = ttk.LabelFrame(left_frame, text="Original Video (DCT only)", padding=10)
        original_group.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(original_group, text="Select original video (required for DCT):").pack(anchor=tk.W)
        original_frame = ttk.Frame(original_group)
        original_frame.pack(fill=tk.X, pady=5)
        
        self.original_video_path = tk.StringVar()
        self.original_entry = ttk.Entry(original_frame, textvariable=self.original_video_path, state='readonly')
        self.original_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(original_frame, text="Browse", command=self.browse_original_video).pack(side=tk.RIGHT)
        
        # Output directory
        extract_output_group = ttk.LabelFrame(left_frame, text="Output Directory", padding=10)
        extract_output_group.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(extract_output_group, text="Where to save extracted file:").pack(anchor=tk.W)
        extract_output_frame = ttk.Frame(extract_output_group)
        extract_output_frame.pack(fill=tk.X, pady=5)
        
        self.extract_output_path = tk.StringVar()
        self.extract_output_entry = ttk.Entry(extract_output_frame, textvariable=self.extract_output_path)
        self.extract_output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(extract_output_frame, text="Browse", command=self.browse_extract_output).pack(side=tk.RIGHT)
        
        # Extract settings
        extract_settings_group = ttk.LabelFrame(left_frame, text="Extraction Settings", padding=10)
        extract_settings_group.pack(fill=tk.X, pady=(0, 10))
        
        # Method selection
        ttk.Label(extract_settings_group, text="Extraction Method:").pack(anchor=tk.W)
        extract_method_frame = ttk.Frame(extract_settings_group)
        extract_method_frame.pack(fill=tk.X, pady=5)
        
        self.extract_method_var = tk.StringVar(value="LSB")
        ttk.Radiobutton(extract_method_frame, text="LSB", variable=self.extract_method_var, value="LSB").pack(side=tk.LEFT)
        ttk.Radiobutton(extract_method_frame, text="DCT", variable=self.extract_method_var, value="DCT").pack(side=tk.LEFT, padx=(20, 0))
        
        # Password for extraction
        self.extract_use_password = tk.BooleanVar()
        ttk.Checkbutton(extract_settings_group, text="Data is password protected", variable=self.extract_use_password, command=self.toggle_extract_password).pack(anchor=tk.W, pady=5)
        
        self.extract_password_frame = ttk.Frame(extract_settings_group)
        self.extract_password_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(self.extract_password_frame, text="Password:").pack(side=tk.LEFT)
        self.extract_password = tk.StringVar()
        self.extract_password_entry = ttk.Entry(self.extract_password_frame, textvariable=self.extract_password, show="*", state='disabled')
        self.extract_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        
        # Action buttons
        extract_button_frame = ttk.Frame(left_frame)
        extract_button_frame.pack(fill=tk.X, pady=10)
        
        self.extract_button = ttk.Button(extract_button_frame, text="Extract Secret File", command=self.extract_file, state='disabled')
        self.extract_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(extract_button_frame, text="Clear All", command=self.clear_extract_fields).pack(side=tk.LEFT)
        
        # === RIGHT PANEL ===
        
        # Extraction info
        extract_info_group = ttk.LabelFrame(right_frame, text="Extraction Information", padding=10)
        extract_info_group.pack(fill=tk.X, pady=(0, 10))
        
        self.extract_info_text = scrolledtext.ScrolledText(extract_info_group, height=8, width=40, state='disabled')
        self.extract_info_text.pack(fill=tk.BOTH, expand=True)
        
        # Extraction log
        extract_log_group = ttk.LabelFrame(right_frame, text="Extraction Log", padding=10)
        extract_log_group.pack(fill=tk.BOTH, expand=True)
        
        self.extract_log_text = scrolledtext.ScrolledText(extract_log_group, height=15, width=40, state='disabled')
        self.extract_log_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_status_bar(self):
        """Setup status bar at bottom"""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 10))
        
        self.status_label = ttk.Label(self.status_frame, text="Ready", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Progress bar for status
        self.status_progress = ttk.Progressbar(self.status_frame, length=200)
        self.status_progress.pack(side=tk.RIGHT, padx=(10, 0))
    
    def setup_logging(self):
        """Setup logging to display in GUI"""
        # Create queue for thread-safe logging
        self.log_queue = queue.Queue()
        
        # Create custom handler
        handler = QueueHandler(self.log_queue)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        # Add handler to root logger
        logging.getLogger().addHandler(handler)
        
        # Start log processing
        self.process_log_queue()
    
    def process_log_queue(self):
        """Process log messages from queue"""
        try:
            while True:
                record = self.log_queue.get_nowait()
                self.add_log_message(record.getMessage())
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_log_queue)
    
    def add_log_message(self, message: str):
        """Add message to log display"""
        current_tab = self.notebook.index(self.notebook.select())
        
        if current_tab == 0:  # Embed tab
            log_widget = self.log_text
        else:  # Extract tab
            log_widget = self.extract_log_text
        
        log_widget.config(state='normal')
        log_widget.insert(tk.END, f"{message}\n")
        log_widget.see(tk.END)
        log_widget.config(state='disabled')
    
    def update_status(self, message: str):
        """Update status bar"""
        self.status_label.config(text=message)
        self.root.update_idletasks()
    
    def toggle_password(self):
        """Toggle password entry state"""
        if self.use_password.get():
            self.password_entry.config(state='normal')
        else:
            self.password_entry.config(state='disabled')
            self.password.set("")
    
    def toggle_extract_password(self):
        """Toggle extract password entry state"""
        if self.extract_use_password.get():
            self.extract_password_entry.config(state='normal')
        else:
            self.extract_password_entry.config(state='disabled')
            self.extract_password.set("")
    
    def browse_cover_video(self):
        """Browse for cover video file"""
        file_path = filedialog.askopenfilename(
            title="Select Cover Video",
            filetypes=[
                ("Video files", "*.mp4 *.avi *.mov *.mkv *.wmv"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.cover_video_path.set(file_path)
            self.load_video_metadata(file_path)
            self.check_embed_ready()
    
    def browse_secret_file(self):
        """Browse for secret file"""
        file_path = filedialog.askopenfilename(
            title="Select Secret File",
            filetypes=[
                ("Text files", "*.txt *.doc *.docx"),
                ("Image files", "*.jpg *.jpeg *.png *.bmp *.gif"),
                ("Video files", "*.mp4 *.avi *.mov *.mkv"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.secret_file_path.set(file_path)
            self.validate_secret_file(file_path)
            self.check_embed_ready()
    
    def browse_output_file(self):
        """Browse for output file location"""
        file_path = filedialog.asksaveasfilename(
            title="Save Output Video As",
            defaultextension=".mp4",
            filetypes=[
                ("MP4 files", "*.mp4"),
                ("AVI files", "*.avi"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.output_path.set(file_path)
            self.check_embed_ready()
    
    def browse_stego_video(self):
        """Browse for stego video file"""
        file_path = filedialog.askopenfilename(
            title="Select Stego Video",
            filetypes=[
                ("Video files", "*.mp4 *.avi *.mov *.mkv *.wmv"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.stego_video_path.set(file_path)
            self.load_stego_video_info(file_path)
            self.check_extract_ready()
    
    def browse_original_video(self):
        """Browse for original video file (DCT)"""
        file_path = filedialog.askopenfilename(
            title="Select Original Video (for DCT extraction)",
            filetypes=[
                ("Video files", "*.mp4 *.avi *.mov *.mkv *.wmv"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.original_video_path.set(file_path)
            self.check_extract_ready()
    
    def browse_extract_output(self):
        """Browse for extraction output directory"""
        dir_path = filedialog.askdirectory(title="Select Output Directory")
        
        if dir_path:
            self.extract_output_path.set(dir_path)
            self.check_extract_ready()
    
    def load_video_metadata(self, video_path: str):
        """Load and display video metadata"""
        try:
            # Validate video
            is_valid, message = self.video_processor.validate_video(video_path)
            
            if not is_valid:
                messagebox.showerror("Invalid Video", message)
                self.cover_video_path.set("")
                return
            
            # Get metadata
            self.current_video_metadata = self.video_processor.get_video_metadata(video_path)
            
            # Display metadata
            self.display_video_metadata(self.current_video_metadata)
            
            # Update capacity information
            self.update_capacity_info()
            
        except Exception as e:
            logger.error(f"Failed to load video metadata: {e}")
            messagebox.showerror("Error", f"Failed to load video: {str(e)}")
    
    def display_video_metadata(self, metadata: VideoMetadata):
        """Display video metadata in the text widget"""
        self.metadata_text.config(state='normal')
        self.metadata_text.delete(1.0, tk.END)
        
        info = f"""File: {os.path.basename(self.cover_video_path.get())}
Size: {VideoProcessor.format_file_size(metadata.file_size)}
Resolution: {metadata.width}x{metadata.height} ({VideoProcessor.get_resolution_name(metadata.width, metadata.height)})
Duration: {VideoProcessor.format_duration(metadata.duration)}
Frame Rate: {metadata.fps:.2f} fps
Frame Count: {metadata.frame_count:,}
Format: {metadata.format.upper()}
Codec: {metadata.codec}
Bitrate: {metadata.bitrate:,} bps ({VideoProcessor.format_file_size(metadata.bitrate // 8)}/s)"""
        
        self.metadata_text.insert(1.0, info)
        self.metadata_text.config(state='disabled')
    
    def update_capacity_info(self):
        """Update capacity information display"""
        if not self.current_video_metadata:
            return
        
        method = self.method_var.get()
        capacity = VideoProcessor.calculate_steganography_capacity(self.current_video_metadata, method)
        
        self.capacity_label.config(text=f"Max capacity ({method}): {VideoProcessor.format_file_size(capacity)}")
        
        # Update secret file size if selected
        if self.secret_file_path.get():
            self.update_secret_file_info()
    
    def validate_secret_file(self, file_path: str):
        """Validate and display secret file information"""
        try:
            is_valid, file_type, message = self.file_validator.validate_secret_file(file_path)
            
            if not is_valid:
                messagebox.showerror("Invalid Secret File", message)
                self.secret_file_path.set("")
                return
            
            self.update_secret_file_info()
            
        except Exception as e:
            logger.error(f"Failed to validate secret file: {e}")
            messagebox.showerror("Error", f"Failed to validate file: {str(e)}")
    
    def update_secret_file_info(self):
        """Update secret file size information"""
        if not self.secret_file_path.get() or not self.current_video_metadata:
            return
        
        file_size = os.path.getsize(self.secret_file_path.get())
        method = self.method_var.get()
        capacity = VideoProcessor.calculate_steganography_capacity(self.current_video_metadata, method)
        
        self.secret_size_label.config(text=f"Secret file size: {VideoProcessor.format_file_size(file_size)}")
        
        if file_size <= capacity:
            remaining = capacity - file_size
            self.capacity_status_label.config(
                text=f"✓ File fits! {VideoProcessor.format_file_size(remaining)} remaining",
                foreground="green"
            )
        else:
            excess = file_size - capacity
            self.capacity_status_label.config(
                text=f"✗ File too large by {VideoProcessor.format_file_size(excess)}",
                foreground="red"
            )
    
    def load_stego_video_info(self, video_path: str):
        """Load stego video information"""
        try:
            metadata = self.video_processor.get_video_metadata(video_path)
            
            self.extract_info_text.config(state='normal')
            self.extract_info_text.delete(1.0, tk.END)
            
            info = f"""Stego Video Information:
File: {os.path.basename(video_path)}
Size: {VideoProcessor.format_file_size(metadata.file_size)}
Resolution: {metadata.width}x{metadata.height}
Duration: {VideoProcessor.format_duration(metadata.duration)}
Frame Count: {metadata.frame_count:,}"""
            
            self.extract_info_text.insert(1.0, info)
            self.extract_info_text.config(state='disabled')
            
        except Exception as e:
            logger.error(f"Failed to load stego video info: {e}")
    
    def check_embed_ready(self):
        """Check if all fields are ready for embedding"""
        ready = (
            self.cover_video_path.get() and
            self.secret_file_path.get() and
            self.output_path.get()
        )
        
        self.embed_button.config(state='normal' if ready else 'disabled')
    
    def check_extract_ready(self):
        """Check if all fields are ready for extraction"""
        method_requires_original = self.extract_method_var.get() == "DCT"
        
        ready = (
            self.stego_video_path.get() and
            self.extract_output_path.get() and
            (not method_requires_original or self.original_video_path.get())
        )
        
        self.extract_button.config(state='normal' if ready else 'disabled')
    
    def clear_embed_fields(self):
        """Clear all embed fields"""
        self.cover_video_path.set("")
        self.secret_file_path.set("")
        self.output_path.set("")
        self.password.set("")
        self.use_password.set(False)
        self.method_var.set("LSB")
        
        self.metadata_text.config(state='normal')
        self.metadata_text.delete(1.0, tk.END)
        self.metadata_text.config(state='disabled')
        
        self.capacity_label.config(text="Select a video to see capacity information")
        self.secret_size_label.config(text="")
        self.capacity_status_label.config(text="")
        
        self.current_video_metadata = None
        self.check_embed_ready()
    
    def clear_extract_fields(self):
        """Clear all extract fields"""
        self.stego_video_path.set("")
        self.original_video_path.set("")
        self.extract_output_path.set("")
        self.extract_password.set("")
        self.extract_use_password.set(False)
        self.extract_method_var.set("LSB")
        
        self.extract_info_text.config(state='normal')
        self.extract_info_text.delete(1.0, tk.END)
        self.extract_info_text.config(state='disabled')
        
        self.check_extract_ready()
    
    def embed_file(self):
        """Embed secret file into cover video"""
        try:
            # Validate inputs
            if not self.validate_embed_inputs():
                return
            
            # Start embedding in separate thread
            thread = threading.Thread(target=self._embed_worker, daemon=True)
            thread.start()
            
        except Exception as e:
            logger.error(f"Embed operation failed: {e}")
            messagebox.showerror("Error", f"Embedding failed: {str(e)}")
    
    def validate_embed_inputs(self) -> bool:
        """Validate all embed inputs"""
        # Check file paths
        if not os.path.exists(self.cover_video_path.get()):
            messagebox.showerror("Error", "Cover video file not found")
            return False
        
        if not os.path.exists(self.secret_file_path.get()):
            messagebox.showerror("Error", "Secret file not found")
            return False
        
        # Check capacity
        if self.current_video_metadata:
            file_size = os.path.getsize(self.secret_file_path.get())
            capacity = VideoProcessor.calculate_steganography_capacity(
                self.current_video_metadata, self.method_var.get()
            )
            
            if file_size > capacity:
                messagebox.showerror("Error", "Secret file is too large for the cover video")
                return False
        
        # Check password
        if self.use_password.get():
            password = self.password.get()
            if not password:
                messagebox.showerror("Error", "Password is required when password protection is enabled")
                return False
            
            is_valid, message = PasswordEncryption.validate_password(password)
            if not is_valid:
                messagebox.showerror("Invalid Password", message)
                return False
        
        return True
    
    def _embed_worker(self):
        """Worker thread for embedding operation"""
        progress_dialog = None
        
        try:
            # Create progress dialog
            self.root.after(0, lambda: self._create_embed_progress_dialog())
            
            # Wait for dialog to be created
            while not hasattr(self, 'embed_progress_dialog'):
                threading.Event().wait(0.1)
            
            progress_dialog = self.embed_progress_dialog
            
            # Setup steganography
            method = self.method_var.get()
            stego = VideoSteganography(method)
            
            # Setup file handler
            password = self.password.get() if self.use_password.get() else None
            file_handler = SecureFileHandler(password)
            
            # Progress callback
            def progress_callback(progress):
                if progress_dialog and not progress_dialog.cancelled:
                    progress_dialog.update_progress(progress, f"Processing... {progress:.1f}%")
            
            # Perform embedding
            logger.info("Starting embedding process...")
            success = stego.embed_file(
                self.cover_video_path.get(),
                self.secret_file_path.get(),
                self.output_path.get(),
                progress_callback
            )
            
            if success:
                self.root.after(0, lambda: self._embed_success())
            else:
                self.root.after(0, lambda: self._embed_error("Embedding failed"))
            
        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self._embed_error(error_msg))
        
        finally:
            if progress_dialog:
                self.root.after(0, lambda: progress_dialog.close())
    
    def _create_embed_progress_dialog(self):
        """Create embed progress dialog"""
        self.embed_progress_dialog = ProgressDialog(
            self.root,
            "Embedding Secret File",
            "Embedding secret file into cover video..."
        )
    
    def _embed_success(self):
        """Handle successful embedding"""
        logger.info("Embedding completed successfully")
        messagebox.showinfo("Success", f"Secret file successfully embedded!\nOutput: {self.output_path.get()}")
        self.update_status("Embedding completed successfully")
    
    def _embed_error(self, error_msg: str):
        """Handle embedding error"""
        logger.error(f"Embedding failed: {error_msg}")
        messagebox.showerror("Embedding Failed", f"Error: {error_msg}")
        self.update_status("Embedding failed")
    
    def extract_file(self):
        """Extract secret file from stego video"""
        try:
            # Validate inputs
            if not self.validate_extract_inputs():
                return
            
            # Start extraction in separate thread
            thread = threading.Thread(target=self._extract_worker, daemon=True)
            thread.start()
            
        except Exception as e:
            logger.error(f"Extract operation failed: {e}")
            messagebox.showerror("Error", f"Extraction failed: {str(e)}")
    
    def validate_extract_inputs(self) -> bool:
        """Validate all extract inputs"""
        # Check stego video
        if not os.path.exists(self.stego_video_path.get()):
            messagebox.showerror("Error", "Stego video file not found")
            return False
        
        # Check original video for DCT
        if self.extract_method_var.get() == "DCT":
            if not self.original_video_path.get():
                messagebox.showerror("Error", "Original video is required for DCT extraction")
                return False
            
            if not os.path.exists(self.original_video_path.get()):
                messagebox.showerror("Error", "Original video file not found")
                return False
        
        # Check output directory
        if not os.path.exists(self.extract_output_path.get()):
            messagebox.showerror("Error", "Output directory does not exist")
            return False
        
        # Check password
        if self.extract_use_password.get():
            password = self.extract_password.get()
            if not password:
                messagebox.showerror("Error", "Password is required for encrypted data")
                return False
        
        return True
    
    def _extract_worker(self):
        """Worker thread for extraction operation"""
        progress_dialog = None
        
        try:
            # Create progress dialog
            self.root.after(0, lambda: self._create_extract_progress_dialog())
            
            # Wait for dialog to be created
            while not hasattr(self, 'extract_progress_dialog'):
                threading.Event().wait(0.1)
            
            progress_dialog = self.extract_progress_dialog
            
            # Setup steganography
            method = self.extract_method_var.get()
            stego = VideoSteganography(method)
            
            # Setup file handler
            password = self.extract_password.get() if self.extract_use_password.get() else None
            file_handler = SecureFileHandler(password)
            
            # Progress callback
            def progress_callback(progress):
                if progress_dialog and not progress_dialog.cancelled:
                    progress_dialog.update_progress(progress, f"Extracting... {progress:.1f}%")
            
            # Perform extraction
            logger.info("Starting extraction process...")
            
            output_file = os.path.join(self.extract_output_path.get(), "extracted_secret")
            original_video = self.original_video_path.get() if method == "DCT" else None
            
            success = stego.extract_file(
                self.stego_video_path.get(),
                output_file,
                original_video,
                progress_callback
            )
            
            if success:
                self.root.after(0, lambda: self._extract_success(output_file))
            else:
                self.root.after(0, lambda: self._extract_error("Extraction failed"))
            
        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self._extract_error(error_msg))
        
        finally:
            if progress_dialog:
                self.root.after(0, lambda: progress_dialog.close())
    
    def _create_extract_progress_dialog(self):
        """Create extract progress dialog"""
        self.extract_progress_dialog = ProgressDialog(
            self.root,
            "Extracting Secret File",
            "Extracting secret file from stego video..."
        )
    
    def _extract_success(self, output_file: str):
        """Handle successful extraction"""
        logger.info("Extraction completed successfully")
        messagebox.showinfo("Success", f"Secret file successfully extracted!\nOutput: {output_file}")
        self.update_status("Extraction completed successfully")
    
    def _extract_error(self, error_msg: str):
        """Handle extraction error"""
        logger.error(f"Extraction failed: {error_msg}")
        messagebox.showerror("Extraction Failed", f"Error: {error_msg}")
        self.update_status("Extraction failed")


class QueueHandler(logging.Handler):
    """Custom logging handler that puts log records in a queue"""
    
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue
    
    def emit(self, record):
        self.log_queue.put(record)