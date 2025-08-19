"""
Video Steganography Application
Main module containing the Tkinter GUI and application logic

Requirements:
- OpenCV (cv2): pip install opencv-python
- NumPy: pip install numpy
- Pillow: pip install Pillow
- python-docx: pip install python-docx
- cryptography: pip install cryptography

Author: AI Assistant
Compatible with: Windows 10, VS Code, Python 3.7+
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, scrolledtext
import cv2
import numpy as np
import os
import threading
import time
from datetime import datetime
from pathlib import Path
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib
matplotlib.use('TkAgg')

# Import steganography modules
from video_processor import VideoProcessor
from file_handler import FileHandler
from steganography_engine import SteganographyEngine


class VideoSteganographyApp:
    """Main application class for Video Steganography GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Video Steganography Tool v1.0")
        self.root.geometry("800x900")
        self.root.resizable(True, True)
        
        # Initialize components
        self.video_processor = VideoProcessor()
        self.file_handler = FileHandler()
        self.stego_engine = SteganographyEngine()
        
        # Variables
        self.cover_video_path = tk.StringVar()
        self.secret_file_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()
        self.use_password = tk.BooleanVar()
        self.algorithm = tk.StringVar(value="LSB")
        
        # Progress tracking
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Ready")
        
        # Video metadata
        self.video_info = {}
        self.max_secret_size = 0
        
        self.setup_gui()
        self.log_message("Application initialized successfully")
    
    def setup_gui(self):
        """Setup the main GUI components"""
        
        # Create main frame with scrollbar
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="Video Steganography Tool", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Hide/Embed tab
        self.hide_frame = ttk.Frame(notebook)
        notebook.add(self.hide_frame, text="Hide Data")
        self.setup_hide_tab()
        
        # Extract tab
        self.extract_frame = ttk.Frame(notebook)
        notebook.add(self.extract_frame, text="Extract Data")
        self.setup_extract_tab()
        
        # Settings tab
        self.settings_frame = ttk.Frame(notebook)
        notebook.add(self.settings_frame, text="Settings")
        self.setup_settings_tab()
        
        # Capacity Analysis tab
        self.capacity_frame = ttk.Frame(notebook)
        notebook.add(self.capacity_frame, text="Capacity Analysis")
        self.setup_capacity_tab()
        
        # Progress and status
        self.setup_progress_section(main_frame)
        
        # Log window
        self.setup_log_section(main_frame)
    
    def setup_hide_tab(self):
        """Setup the hide/embed data tab"""
        
        # Cover video selection
        cover_frame = ttk.LabelFrame(self.hide_frame, text="Cover Video", padding=10)
        cover_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Entry(cover_frame, textvariable=self.cover_video_path, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(cover_frame, text="Browse", command=self.select_cover_video).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Video info display
        self.video_info_frame = ttk.LabelFrame(self.hide_frame, text="Video Information", padding=10)
        self.video_info_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.video_info_text = scrolledtext.ScrolledText(self.video_info_frame, height=4, width=70)
        self.video_info_text.pack(fill=tk.BOTH, expand=True)
        
        # Secret file selection
        secret_frame = ttk.LabelFrame(self.hide_frame, text="Secret File", padding=10)
        secret_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Entry(secret_frame, textvariable=self.secret_file_path, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(secret_frame, text="Browse", command=self.select_secret_file).pack(side=tk.RIGHT, padx=(5, 0))
        
        # File size warning
        self.size_warning_frame = ttk.Frame(self.hide_frame)
        self.size_warning_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.size_warning_label = ttk.Label(self.size_warning_frame, text="", foreground="red")
        self.size_warning_label.pack()
        
        # Capacity visualization button
        capacity_viz_frame = ttk.Frame(self.hide_frame)
        capacity_viz_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(capacity_viz_frame, text="Show Capacity Comparison", 
                  command=self.show_capacity_comparison).pack(pady=5)
        
        # Password section
        password_frame = ttk.LabelFrame(self.hide_frame, text="Encryption (Optional)", padding=10)
        password_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Checkbutton(password_frame, text="Use password encryption", 
                       variable=self.use_password).pack(anchor=tk.W)
        
        pwd_entry_frame = ttk.Frame(password_frame)
        pwd_entry_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(pwd_entry_frame, text="Password:").pack(side=tk.LEFT)
        self.password_entry = ttk.Entry(pwd_entry_frame, textvariable=self.password, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # Output selection
        output_frame = ttk.LabelFrame(self.hide_frame, text="Output Video", padding=10)
        output_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Entry(output_frame, textvariable=self.output_path, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(output_frame, text="Browse", command=self.select_output_path).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Hide button
        ttk.Button(self.hide_frame, text="Hide Data in Video", 
                  command=self.hide_data_thread, style="Accent.TButton").pack(pady=20)
    
    def setup_extract_tab(self):
        """Setup the extract data tab"""
        
        # Input video selection
        input_frame = ttk.LabelFrame(self.extract_frame, text="Steganographic Video", padding=10)
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.extract_video_path = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.extract_video_path, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(input_frame, text="Browse", command=self.select_extract_video).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Password section for extraction
        extract_password_frame = ttk.LabelFrame(self.extract_frame, text="Decryption (If Used)", padding=10)
        extract_password_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.extract_password = tk.StringVar()
        self.use_extract_password = tk.BooleanVar()
        
        ttk.Checkbutton(extract_password_frame, text="File is password protected", 
                       variable=self.use_extract_password).pack(anchor=tk.W)
        
        extract_pwd_frame = ttk.Frame(extract_password_frame)
        extract_pwd_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(extract_pwd_frame, text="Password:").pack(side=tk.LEFT)
        ttk.Entry(extract_pwd_frame, textvariable=self.extract_password, show="*", width=30).pack(side=tk.LEFT, padx=(5, 0))
        
        # Output directory
        extract_output_frame = ttk.LabelFrame(self.extract_frame, text="Output Directory", padding=10)
        extract_output_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.extract_output_path = tk.StringVar()
        ttk.Entry(extract_output_frame, textvariable=self.extract_output_path, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(extract_output_frame, text="Browse", command=self.select_extract_output).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Extract button
        ttk.Button(self.extract_frame, text="Extract Hidden Data", 
                  command=self.extract_data_thread, style="Accent.TButton").pack(pady=20)
    
    def setup_settings_tab(self):
        """Setup the settings tab"""
        
        # Algorithm selection
        algo_frame = ttk.LabelFrame(self.settings_frame, text="Steganography Algorithm", padding=10)
        algo_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Radiobutton(algo_frame, text="LSB (Least Significant Bit)", 
                       variable=self.algorithm, value="LSB").pack(anchor=tk.W)
        ttk.Radiobutton(algo_frame, text="DCT (Discrete Cosine Transform)", 
                       variable=self.algorithm, value="DCT").pack(anchor=tk.W)
        
        # Supported formats info
        formats_frame = ttk.LabelFrame(self.settings_frame, text="Supported File Formats", padding=10)
        formats_frame.pack(fill=tk.X, pady=(0, 10))
        
        formats_text = """Cover Videos: .mp4, .avi, .mov, .mkv
Secret Files: 
• Text: .txt
• Documents: .doc, .docx  
• Images: .jpg, .jpeg, .png, .bmp, .gif
• Videos: .mp4, .avi, .mov, .mkv
• Audio: .mp3, .wav, .flac
Maximum Cover Video Size: 50 MB
Supported Resolutions: 480p, 720p, 1080p"""
        
        ttk.Label(formats_frame, text=formats_text, justify=tk.LEFT).pack(anchor=tk.W)
    
    def setup_capacity_tab(self):
        """Setup the capacity analysis tab"""
        capacity_frame = ttk.LabelFrame(self.capacity_frame, text="Capacity Analysis", padding=10)
        capacity_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Resolution selection
        resolution_frame = ttk.LabelFrame(capacity_frame, text="Select Resolution", padding=10)
        resolution_frame.pack(fill=tk.X, pady=(0, 10))

        self.resolution_var = tk.StringVar(value="480p")
        ttk.Radiobutton(resolution_frame, text="480p", variable=self.resolution_var, value="480p").pack(anchor=tk.W)
        ttk.Radiobutton(resolution_frame, text="720p", variable=self.resolution_var, value="720p").pack(anchor=tk.W)
        ttk.Radiobutton(resolution_frame, text="1080p", variable=self.resolution_var, value="1080p").pack(anchor=tk.W)

        # Algorithm selection
        algo_frame = ttk.LabelFrame(capacity_frame, text="Steganography Algorithm", padding=10)
        algo_frame.pack(fill=tk.X, pady=(0, 10))

        self.algorithm_var = tk.StringVar(value="LSB")
        ttk.Radiobutton(algo_frame, text="LSB (Least Significant Bit)", 
                       variable=self.algorithm_var, value="LSB").pack(anchor=tk.W)
        ttk.Radiobutton(algo_frame, text="DCT (Discrete Cosine Transform)", 
                       variable=self.algorithm_var, value="DCT").pack(anchor=tk.W)

        # Capacity plot
        self.capacity_plot_frame = ttk.LabelFrame(capacity_frame, text="Capacity Analysis Plot", padding=10)
        self.capacity_plot_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.capacity_plot_canvas = FigureCanvasTkAgg(plt.figure(figsize=(6, 4)), master=self.capacity_plot_frame)
        self.capacity_plot_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Calculate and display capacity
        self.calculate_and_display_capacity()

    def setup_progress_section(self, parent):
        """Setup progress bar and status"""
        
        progress_frame = ttk.LabelFrame(parent, text="Progress", padding=10)
        progress_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                          maximum=100, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))
        
        self.status_label = ttk.Label(progress_frame, textvariable=self.status_var)
        self.status_label.pack()
    
    def setup_log_section(self, parent):
        """Setup log window"""
        
        log_frame = ttk.LabelFrame(parent, text="Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, width=70)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Clear log button
        ttk.Button(log_frame, text="Clear Log", command=self.clear_log).pack(pady=(5, 0))
    
    def log_message(self, message):
        """Add message to log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def clear_log(self):
        """Clear the log window"""
        self.log_text.delete(1.0, tk.END)
    
    def select_cover_video(self):
        """Select cover video file"""
        filetypes = [
            ("Video files", "*.mp4 *.avi *.mov *.mkv"),
            ("All files", "*.*")
        ]
        
        filename = filedialog.askopenfilename(
            title="Select Cover Video",
            filetypes=filetypes
        )
        
        if filename:
            self.cover_video_path.set(filename)
            self.analyze_video(filename)
    
    def select_secret_file(self):
        """Select secret file to hide"""
        filetypes = [
            ("All supported files", "*.txt *.doc *.docx *.jpg *.jpeg *.png *.bmp *.gif *.mp4 *.avi *.mov *.mkv *.mp3 *.wav *.flac"),
            ("Text files", "*.txt"),
            ("Document files", "*.doc *.docx"),
            ("Image files", "*.jpg *.jpeg *.png *.bmp *.gif"),
            ("Video files", "*.mp4 *.avi *.mov *.mkv"),
            ("Audio files", "*.mp3 *.wav *.flac"),
            ("All files", "*.*")
        ]
        
        filename = filedialog.askopenfilename(
            title="Select Secret File",
            filetypes=filetypes
        )
        
        if filename:
            self.secret_file_path.set(filename)
            self.check_file_size_compatibility()
    
    def select_output_path(self):
        """Select output path for steganographic video"""
        filename = filedialog.asksaveasfilename(
            title="Save Steganographic Video As",
            defaultextension=".mp4",
            filetypes=[("MP4 files", "*.mp4"), ("AVI files", "*.avi")]
        )
        
        if filename:
            self.output_path.set(filename)
    
    def select_extract_video(self):
        """Select video for data extraction"""
        filetypes = [
            ("Video files", "*.mp4 *.avi *.mov *.mkv"),
            ("All files", "*.*")
        ]
        
        filename = filedialog.askopenfilename(
            title="Select Steganographic Video",
            filetypes=filetypes
        )
        
        if filename:
            self.extract_video_path.set(filename)
    
    def select_extract_output(self):
        """Select output directory for extracted files"""
        directory = filedialog.askdirectory(title="Select Output Directory")
        
        if directory:
            self.extract_output_path.set(directory)
    
    def analyze_video(self, video_path):
        """Analyze video and display information"""
        try:
            self.log_message(f"Analyzing video: {os.path.basename(video_path)}")
            
            # Get video info
            info = self.video_processor.get_video_info(video_path)
            self.video_info = info
            
            # Check file size
            file_size_mb = info['file_size'] / (1024 * 1024)
            if file_size_mb > 50:
                messagebox.showwarning("File Size Warning", 
                                     f"Video file is {file_size_mb:.1f} MB. "
                                     "Files larger than 50 MB may not be fully supported.")
            
            # Calculate maximum secret file size
            self.max_secret_size = self.stego_engine.calculate_max_payload_size(
                info['width'], info['height'], info['frame_count'], self.algorithm.get()
            )
            
            # Display info
            info_text = f"""File: {os.path.basename(video_path)}
Size: {file_size_mb:.2f} MB
Resolution: {info['width']}x{info['height']} ({self.get_resolution_name(info['width'], info['height'])})
Duration: {info['duration']:.2f} seconds
Frame Rate: {info['fps']:.2f} fps
Frame Count: {info['frame_count']}
Codec: {info['codec']}
Maximum Secret File Size: {self.max_secret_size / 1024:.2f} KB"""
            
            self.video_info_text.delete(1.0, tk.END)
            self.video_info_text.insert(1.0, info_text)
            
            self.log_message(f"Video analysis complete. Max payload: {self.max_secret_size / 1024:.2f} KB")
            
        except Exception as e:
            self.log_message(f"Error analyzing video: {str(e)}")
            messagebox.showerror("Error", f"Failed to analyze video:\n{str(e)}")
    
    def get_resolution_name(self, width, height):
        """Get resolution name (480p, 720p, 1080p)"""
        if height <= 480:
            return "480p"
        elif height <= 720:
            return "720p"
        elif height <= 1080:
            return "1080p"
        else:
            return f"{height}p"
    
    def check_file_size_compatibility(self):
        """Check if secret file can fit in cover video"""
        if not self.secret_file_path.get() or self.max_secret_size == 0:
            return
        
        try:
            secret_size = os.path.getsize(self.secret_file_path.get())
            
            if secret_size > self.max_secret_size:
                warning_text = f"⚠️ Secret file ({secret_size / 1024:.2f} KB) is too large!\nMaximum size: {self.max_secret_size / 1024:.2f} KB"
                self.size_warning_label.config(text=warning_text, foreground="red")
                self.log_message(f"Warning: Secret file too large ({secret_size / 1024:.2f} KB > {self.max_secret_size / 1024:.2f} KB)")
            else:
                self.size_warning_label.config(text=f"✓ File size OK ({secret_size / 1024:.2f} KB)", foreground="green")
                self.log_message(f"Secret file size OK: {secret_size / 1024:.2f} KB")
                
        except Exception as e:
            self.log_message(f"Error checking file size: {str(e)}")
    
    def show_capacity_comparison_auto(self, file_size_kb):
        """Automatically show capacity comparison without user input"""
        try:
            if not self.video_info:
                return
            
            algorithm = self.algorithm_var.get()
            width = self.video_info['width']
            height = self.video_info['height']
            frame_count = self.video_info['frame_count']
            
            max_payload_size = self.stego_engine.calculate_max_payload_size(
                width, height, frame_count, algorithm
            )
            max_payload_size_kb = max_payload_size / 1024
            
            # Create a new window for the plot
            plot_window = tk.Toplevel(self.root)
            plot_window.title("Capacity Analysis")
            plot_window.geometry("600x400")
            
            # Create plot
            fig, ax = plt.subplots(figsize=(8, 6))
            
            # Create bars with different colors
            colors = ['red' if file_size_kb > max_payload_size_kb else 'green', 'blue']
            bars = ax.bar(['Selected File Size', 'Maximum Capacity'], 
                         [file_size_kb, max_payload_size_kb], 
                         color=colors)
            
            # Add value labels on bars
            for bar, value in zip(bars, [file_size_kb, max_payload_size_kb]):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                       f'{value:.1f} KB', ha='center', va='bottom')
            
            ax.set_ylabel('Size (KB)')
            ax.set_title(f'Capacity Analysis\n{width}x{height} Video, {frame_count} frames')
            ax.grid(True, linestyle='--', alpha=0.7)
            
            # Add status message
            if file_size_kb > max_payload_size_kb:
                status_text = '⚠️ File too large for this video!'
                status_color = 'red'
            else:
                status_text = '✓ File size is compatible'
                status_color = 'green'
            
            ax.text(0.5, 0.95, status_text, 
                   transform=ax.transAxes, ha='center', va='top',
                   bbox=dict(boxstyle="round,pad=0.3", facecolor=status_color, alpha=0.7))
            
            # Create canvas and display
            canvas = FigureCanvasTkAgg(fig, master=plot_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add close button
            ttk.Button(plot_window, text="Close", command=plot_window.destroy).pack(pady=5)
            
        except Exception as e:
            self.log_message(f"Error showing automatic capacity comparison: {str(e)}")
    
    def hide_data_thread(self):
        """Start hide data operation in separate thread"""
        thread = threading.Thread(target=self.hide_data)
        thread.daemon = True
        thread.start()
    
    def extract_data_thread(self):
        """Start extract data operation in separate thread"""
        thread = threading.Thread(target=self.extract_data)
        thread.daemon = True
        thread.start()
    
    def hide_data(self):
        """Hide data in video"""
        try:
            # Validate inputs
            if not self.cover_video_path.get():
                messagebox.showerror("Error", "Please select a cover video")
                return
            
            if not self.secret_file_path.get():
                messagebox.showerror("Error", "Please select a secret file")
                return
            
            if not self.output_path.get():
                messagebox.showerror("Error", "Please specify output path")
                return
            
            # Check if output is not AVI and warn user
            if not self.output_path.get().lower().endswith('.avi'):
                result = messagebox.askyesno("Format Warning", 
                    "You're not using AVI format. Video compression may corrupt hidden data.\n\n"
                    "Do you want to continue anyway?")
                if not result:
                    return
            
            self.status_var.set("Hiding data...")
            self.progress_var.set(10)
            self.log_message("Starting data hiding process...")
            
            # Read secret file
            secret_data = self.file_handler.read_file(self.secret_file_path.get())
            if secret_data is None:
                messagebox.showerror("Error", "Failed to read secret file")
                return
            
            # Prepare metadata
            filename = os.path.basename(self.secret_file_path.get())
            extension = os.path.splitext(filename)[1]
            
            metadata = {
                'filename': filename,
                'extension': extension,
                'size': len(secret_data),
                'encrypted': self.use_password.get() and bool(self.password.get())
            }
            
            # Encrypt if password is provided
            if self.use_password.get() and self.password.get():
                self.log_message("Encrypting data...")
                try:
                    secret_data = self.encrypt_data(secret_data, self.password.get())
                    self.log_message("Data encrypted successfully")
                except Exception as e:
                    self.log_message(f"Encryption failed: {str(e)}")
                    messagebox.showerror("Error", f"Encryption failed: {str(e)}")
                    return
            
            self.progress_var.set(30)
            
            # Hide data using backup method for reliability
            success = self.stego_engine.hide_data_with_backup(
                self.cover_video_path.get(),
                self.output_path.get(),
                secret_data,
                metadata,
                self.algorithm.get(),
                self.update_progress
            )
            
            if success:
                self.progress_var.set(100)
                self.status_var.set("Data hidden successfully!")
                self.log_message(f"Success! Steganographic video saved to: {self.output_path.get()}")
                messagebox.showinfo("Success", 
                    f"Data hidden successfully in video!\n"
                    f"Saved to: {self.output_path.get()}\n\n"
                    f"Note: A backup file was created for reliable extraction.\n"
                    f"Use AVI format for best compatibility.")
            else:
                self.log_message("Failed to hide data")
                messagebox.showerror("Error", "Failed to hide data in video")
                self.status_var.set("Error occurred")
            
        except Exception as e:
            self.log_message(f"Error during hiding process: {str(e)}")
            messagebox.showerror("Error", f"Failed to hide data:\n{str(e)}")
            self.status_var.set("Error occurred")
    
    def extract_data(self):
        """Extract data from video"""
        try:
            # Validate inputs
            if not self.extract_video_path.get():
                messagebox.showerror("Error", "Please select a steganographic video")
                return
            
            if not self.extract_output_path.get():
                messagebox.showerror("Error", "Please specify output directory")
                return
            
            self.status_var.set("Extracting data...")
            self.progress_var.set(10)
            self.log_message("Starting data extraction process...")
            
            # Extract data using backup method for reliability
            result = self.stego_engine.extract_data_with_backup(
                self.extract_video_path.get(),
                self.algorithm.get(),
                self.update_progress
            )
            
            if result is None:
                self.log_message("No hidden data found in video")
                messagebox.showwarning("Warning", "No hidden data found in video")
                return
            
            secret_data, metadata = result
            self.progress_var.set(70)
            
            # Check if data was encrypted during hiding
            if metadata.get('encrypted', False):
                # Data was encrypted, password is required
                if not self.use_extract_password.get() or not self.extract_password.get():
                    messagebox.showerror("Error", "This file is password protected. Please enter the password.")
                    return
                
                self.log_message("Decrypting extracted data...")
                try:
                    secret_data = self.decrypt_data(secret_data, self.extract_password.get())
                    self.log_message("Data decrypted successfully")
                except Exception as e:
                    self.log_message(f"Decryption failed: {str(e)}")
                    messagebox.showerror("Error", "Invalid password or corrupted data")
                    return
            else:
                # Data was not encrypted, password should not be used
                if self.use_extract_password.get() and self.extract_password.get():
                    self.log_message("Warning: Password provided but data was not encrypted")
                    # Ask user if they want to proceed without password
                    result = messagebox.askyesno("Password Warning", 
                        "This file was not encrypted during hiding, but you provided a password.\n\n"
                        "Do you want to proceed without using the password?")
                    if not result:
                        return
            
            self.progress_var.set(90)
            
            # Save extracted file
            output_filename = os.path.join(
                self.extract_output_path.get(),
                metadata.get('filename', f"extracted_file{metadata.get('extension', '.bin')}")
            )
            
            self.file_handler.write_file(output_filename, secret_data)
            
            self.progress_var.set(100)
            self.status_var.set("Data extracted successfully!")
            self.log_message(f"Success! Extracted file saved to: {output_filename}")
            messagebox.showinfo("Success", f"Data extracted successfully!\nSaved to: {output_filename}")
            
        except Exception as e:
            self.log_message(f"Error during extraction process: {str(e)}")
            messagebox.showerror("Error", f"Failed to extract data:\n{str(e)}")
            self.status_var.set("Error occurred")
    
    def update_progress(self, percentage):
        """Update progress bar"""
        self.progress_var.set(percentage)
        self.root.update_idletasks()
    
    def encrypt_data(self, data, password):
        """Encrypt data using password"""
        # Generate key from password
        password_bytes = password.encode()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        
        # Encrypt data
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        
        # Return salt + encrypted data
        return salt + encrypted_data
    
    def decrypt_data(self, encrypted_data, password):
        """Decrypt data using password"""
        # Extract salt and encrypted data
        salt = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]
        
        # Generate key from password
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        
        # Decrypt data
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        return decrypted_data

    def calculate_and_display_capacity(self):
        """Calculate and display capacity analysis plot"""
        try:
            # Get current resolution and algorithm
            resolution = self.resolution_var.get()
            algorithm = self.algorithm_var.get()

            # Determine resolution dimensions
            if resolution == "480p":
                width, height = 640, 480
            elif resolution == "720p":
                width, height = 1280, 720
            elif resolution == "1080p":
                width, height = 1920, 1080
            else:
                messagebox.showerror("Error", "Unsupported resolution selected.")
                return

            # Calculate capacity for different file sizes
            file_sizes = np.linspace(1, 1000, 100) # KB to KB
            max_payload_sizes = []

            for file_size_kb in file_sizes:
                max_payload_size = self.stego_engine.calculate_max_payload_size(
                    width, height, 1, # Assuming 1 frame for simplicity in this plot
                    algorithm
                )
                max_payload_sizes.append(max_payload_size / 1024) # Convert to KB

            # Create plot
            plt.figure(figsize=(8, 6))
            plt.plot(file_sizes, max_payload_sizes, marker='o', linestyle='-', color='b')
            plt.title(f'Capacity Analysis for {resolution} Resolution')
            plt.xlabel('Secret File Size (KB)')
            plt.ylabel('Maximum Payload Size (KB)')
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.ylim(0, max(max_payload_sizes) * 1.2) # Add some padding

            # Update canvas
            self.capacity_plot_canvas.draw()
            self.capacity_plot_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        except Exception as e:
            self.log_message(f"Error calculating capacity: {str(e)}")
            messagebox.showerror("Error", f"Failed to calculate capacity:\n{str(e)}")

    def show_capacity_comparison(self):
        """Show a bar graph comparing the selected file size with the maximum capacity"""
        try:
            # Check if we have video information
            if not self.video_info:
                messagebox.showwarning("Warning", "Please select a cover video first to get accurate capacity information.")
                return
            
            # Check if a secret file is selected
            if not self.secret_file_path.get():
                messagebox.showwarning("Warning", "Please select a secret file first to analyze its size.")
                return
            
            # Get current algorithm
            algorithm = self.algorithm_var.get()
            
            # Use actual video information
            width = self.video_info['width']
            height = self.video_info['height']
            frame_count = self.video_info['frame_count']
            
            # Calculate maximum capacity
            max_payload_size = self.stego_engine.calculate_max_payload_size(
                width, height, frame_count, algorithm
            )
            max_payload_size_kb = max_payload_size / 1024
            
            # Automatically detect the selected secret file size
            try:
                secret_file_size = os.path.getsize(self.secret_file_path.get())
                file_size_kb = secret_file_size / 1024
                
                # Get file info for display
                file_info = self.file_handler.get_file_info(self.secret_file_path.get())
                file_name = file_info['name']
                file_type = file_info['type']
                
                self.log_message(f"Analyzing file: {file_name} ({file_type}, {file_size_kb:.2f} KB)")
                
            except Exception as e:
                self.log_message(f"Error reading secret file: {str(e)}")
                messagebox.showerror("Error", f"Failed to read secret file:\n{str(e)}")
                return
            
            # Create a new window for the plot
            plot_window = tk.Toplevel(self.root)
            plot_window.title("Capacity Comparison")
            plot_window.geometry("600x400")
            
            # Create plot
            fig, ax = plt.subplots(figsize=(8, 6))
            
            # Create bars with different colors based on whether file fits
            colors = ['red' if file_size_kb > max_payload_size_kb else 'green', 'blue']
            bars = ax.bar(['Selected File Size', 'Maximum Capacity'], 
                         [file_size_kb, max_payload_size_kb], 
                         color=colors)
            
            # Add value labels on bars
            for bar, value in zip(bars, [file_size_kb, max_payload_size_kb]):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                       f'{value:.1f} KB', ha='center', va='bottom')
            
            ax.set_ylabel('Size (KB)')
            ax.set_title(f'Capacity Comparison\n{width}x{height} Video, {frame_count} frames\nFile: {file_name}')
            ax.grid(True, linestyle='--', alpha=0.7)
            
            # Add status message
            if file_size_kb > max_payload_size_kb:
                status_text = '⚠️ File too large for this video!'
                status_color = 'red'
            else:
                status_text = '✓ File size is compatible'
                status_color = 'green'
            
            ax.text(0.5, 0.95, status_text, 
                   transform=ax.transAxes, ha='center', va='top',
                   bbox=dict(boxstyle="round,pad=0.3", facecolor=status_color, alpha=0.7))
            
            # Create canvas and display
            canvas = FigureCanvasTkAgg(fig, master=plot_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Add close button
            ttk.Button(plot_window, text="Close", command=plot_window.destroy).pack(pady=5)
            
            self.log_message(f"Capacity comparison: File {file_size_kb:.2f} KB vs Max {max_payload_size_kb:.1f} KB")
            
        except Exception as e:
            self.log_message(f"Error showing capacity comparison: {str(e)}")
            messagebox.showerror("Error", f"Failed to show capacity comparison:\n{str(e)}")


def main():
    """Main function to run the application"""
    root = tk.Tk()
    
    # Set application icon (if available)
    try:
        root.iconbitmap('icon.ico')  # Optional: add your icon file
    except:
        pass
    
    # Configure style
    style = ttk.Style()
    style.theme_use('clam')  # Modern theme
    
    # Create and run application
    app = VideoSteganographyApp(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("Application terminated by user")


if __name__ == "__main__":
    main()