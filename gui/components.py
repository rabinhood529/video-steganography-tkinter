"""
GUI components and utilities for video steganography application.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from typing import Optional, Callable, Dict, Any
import threading
import queue
from utils.logger import get_logger

logger = get_logger(__name__)


class ProgressDialog:
    """Progress dialog for long-running operations."""
    
    def __init__(self, parent: tk.Tk, title: str = "Processing..."):
        self.parent = parent
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x150")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (
            parent.winfo_rootx() + 50,
            parent.winfo_rooty() + 50
        ))
        
        # Progress variables
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Initializing...")
        self.cancelled = False
        
        self._create_widgets()
        
    def _create_widgets(self):
        """Create dialog widgets."""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status label
        status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                               font=('Arial', 10))
        status_label.pack(pady=(0, 10))
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(
            main_frame, 
            variable=self.progress_var,
            maximum=100,
            length=350
        )
        self.progress_bar.pack(pady=(0, 10))
        
        # Progress percentage label
        self.percent_label = ttk.Label(main_frame, text="0%", font=('Arial', 9))
        self.percent_label.pack(pady=(0, 10))
        
        # Cancel button
        self.cancel_btn = ttk.Button(main_frame, text="Cancel", 
                                   command=self._cancel)
        self.cancel_btn.pack()
        
        # Handle window close
        self.dialog.protocol("WM_DELETE_WINDOW", self._cancel)
    
    def update_progress(self, progress: int, status: str = None):
        """Update progress bar and status."""
        self.progress_var.set(progress)
        self.percent_label.config(text=f"{progress}%")
        
        if status:
            self.status_var.set(status)
        
        self.dialog.update()
    
    def _cancel(self):
        """Cancel the operation."""
        self.cancelled = True
        self.dialog.destroy()
    
    def is_cancelled(self) -> bool:
        """Check if operation was cancelled."""
        return self.cancelled
    
    def close(self):
        """Close the dialog."""
        if self.dialog.winfo_exists():
            self.dialog.destroy()


class FileInfoFrame:
    """Frame to display file information."""
    
    def __init__(self, parent: tk.Widget, title: str):
        self.frame = ttk.LabelFrame(parent, text=title, padding="10")
        self.info_vars = {}
        self._create_widgets()
    
    def _create_widgets(self):
        """Create information display widgets."""
        # File path
        ttk.Label(self.frame, text="File:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.info_vars['path'] = tk.StringVar(value="No file selected")
        ttk.Label(self.frame, textvariable=self.info_vars['path'], 
                 foreground="blue").grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # File size
        ttk.Label(self.frame, text="Size:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.info_vars['size'] = tk.StringVar(value="-")
        ttk.Label(self.frame, textvariable=self.info_vars['size']).grid(
            row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # File format
        ttk.Label(self.frame, text="Format:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.info_vars['format'] = tk.StringVar(value="-")
        ttk.Label(self.frame, textvariable=self.info_vars['format']).grid(
            row=2, column=1, sticky=tk.W, padx=(10, 0), pady=2)
    
    def update_info(self, info: Dict[str, str]):
        """Update displayed information."""
        for key, value in info.items():
            if key in self.info_vars:
                self.info_vars[key].set(value)


class VideoInfoFrame(FileInfoFrame):
    """Extended frame for video file information."""
    
    def _create_widgets(self):
        """Create video-specific information widgets."""
        super()._create_widgets()
        
        # Resolution
        ttk.Label(self.frame, text="Resolution:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.info_vars['resolution'] = tk.StringVar(value="-")
        ttk.Label(self.frame, textvariable=self.info_vars['resolution']).grid(
            row=3, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Duration
        ttk.Label(self.frame, text="Duration:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.info_vars['duration'] = tk.StringVar(value="-")
        ttk.Label(self.frame, textvariable=self.info_vars['duration']).grid(
            row=4, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # FPS
        ttk.Label(self.frame, text="FPS:").grid(row=5, column=0, sticky=tk.W, pady=2)
        self.info_vars['fps'] = tk.StringVar(value="-")
        ttk.Label(self.frame, textvariable=self.info_vars['fps']).grid(
            row=5, column=1, sticky=tk.W, padx=(10, 0), pady=2)


class CapacityFrame:
    """Frame to display embedding capacity information."""
    
    def __init__(self, parent: tk.Widget):
        self.frame = ttk.LabelFrame(parent, text="Embedding Capacity", padding="10")
        self.capacity_vars = {}
        self._create_widgets()
    
    def _create_widgets(self):
        """Create capacity display widgets."""
        # LSB capacity
        ttk.Label(self.frame, text="LSB Algorithm:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.capacity_vars['lsb'] = tk.StringVar(value="Calculate capacity first")
        ttk.Label(self.frame, textvariable=self.capacity_vars['lsb'], 
                 foreground="green").grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # DCT capacity
        ttk.Label(self.frame, text="DCT Algorithm:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.capacity_vars['dct'] = tk.StringVar(value="Calculate capacity first")
        ttk.Label(self.frame, textvariable=self.capacity_vars['dct'], 
                 foreground="green").grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Warning label
        self.warning_var = tk.StringVar()
        self.warning_label = ttk.Label(self.frame, textvariable=self.warning_var, 
                                     foreground="red", font=('Arial', 9, 'bold'))
        self.warning_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
    
    def update_capacity(self, lsb_capacity: str, dct_capacity: str):
        """Update capacity information."""
        self.capacity_vars['lsb'].set(lsb_capacity)
        self.capacity_vars['dct'].set(dct_capacity)
    
    def show_warning(self, message: str):
        """Show capacity warning."""
        self.warning_var.set(message)
    
    def clear_warning(self):
        """Clear capacity warning."""
        self.warning_var.set("")


class LogFrame:
    """Frame for displaying application logs."""
    
    def __init__(self, parent: tk.Widget):
        self.frame = ttk.LabelFrame(parent, text="Application Log", padding="5")
        self._create_widgets()
        
        # Message queue for thread-safe logging
        self.log_queue = queue.Queue()
        self._check_queue()
    
    def _create_widgets(self):
        """Create log display widgets."""
        # Text widget with scrollbar
        text_frame = ttk.Frame(self.frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(
            text_frame, 
            height=8, 
            width=80,
            font=('Consolas', 9),
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Control buttons
        btn_frame = ttk.Frame(self.frame)
        btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(btn_frame, text="Clear Log", 
                  command=self.clear_log).pack(side=tk.LEFT)
        
        ttk.Button(btn_frame, text="Save Log", 
                  command=self.save_log).pack(side=tk.LEFT, padx=(5, 0))
    
    def add_log(self, message: str, level: str = "INFO"):
        """Add log message (thread-safe)."""
        self.log_queue.put((message, level))
    
    def _check_queue(self):
        """Check for new log messages."""
        try:
            while True:
                message, level = self.log_queue.get_nowait()
                self._insert_log(message, level)
        except queue.Empty:
            pass
        
        # Schedule next check
        self.frame.after(100, self._check_queue)
    
    def _insert_log(self, message: str, level: str):
        """Insert log message into text widget."""
        self.log_text.config(state=tk.NORMAL)
        
        # Add timestamp
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] {level}: {message}\n"
        
        self.log_text.insert(tk.END, log_line)
        
        # Color coding
        if level == "ERROR":
            self.log_text.tag_add("error", "end-2l", "end-1l")
            self.log_text.tag_config("error", foreground="red")
        elif level == "WARNING":
            self.log_text.tag_add("warning", "end-2l", "end-1l")
            self.log_text.tag_config("warning", foreground="orange")
        elif level == "SUCCESS":
            self.log_text.tag_add("success", "end-2l", "end-1l")
            self.log_text.tag_config("success", foreground="green")
        
        # Auto-scroll to bottom
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def clear_log(self):
        """Clear log contents."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def save_log(self):
        """Save log to file."""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if file_path:
                content = self.log_text.get(1.0, tk.END)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Log saved to {file_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {str(e)}")


class PasswordDialog:
    """Dialog for password input."""
    
    def __init__(self, parent: tk.Tk, title: str = "Enter Password"):
        self.parent = parent
        self.password = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("300x150")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (
            parent.winfo_rootx() + 100,
            parent.winfo_rooty() + 100
        ))
        
        self._create_widgets()
        
        # Focus on password entry
        self.password_entry.focus_set()
    
    def _create_widgets(self):
        """Create dialog widgets."""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Password label and entry
        ttk.Label(main_frame, text="Password:").pack(anchor=tk.W, pady=(0, 5))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                       show="*", width=30)
        self.password_entry.pack(pady=(0, 10))
        self.password_entry.bind('<Return>', lambda e: self._ok())
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=(10, 0))
        
        ttk.Button(btn_frame, text="OK", command=self._ok).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Cancel", command=self._cancel).pack(side=tk.LEFT)
        
        # Handle window close
        self.dialog.protocol("WM_DELETE_WINDOW", self._cancel)
    
    def _ok(self):
        """Handle OK button."""
        self.password = self.password_var.get()
        self.dialog.destroy()
    
    def _cancel(self):
        """Handle Cancel button."""
        self.password = None
        self.dialog.destroy()
    
    def get_password(self) -> Optional[str]:
        """Get entered password."""
        self.dialog.wait_window()
        return self.password


def show_error(parent: tk.Widget, title: str, message: str):
    """Show error message dialog."""
    messagebox.showerror(title, message, parent=parent)


def show_info(parent: tk.Widget, title: str, message: str):
    """Show information message dialog."""
    messagebox.showinfo(title, message, parent=parent)


def show_warning(parent: tk.Widget, title: str, message: str):
    """Show warning message dialog."""
    messagebox.showwarning(title, message, parent=parent)


def ask_yes_no(parent: tk.Widget, title: str, message: str) -> bool:
    """Show yes/no question dialog."""
    return messagebox.askyesno(title, message, parent=parent)


def select_file(parent: tk.Widget, title: str, filetypes: list) -> Optional[str]:
    """Show file selection dialog."""
    return filedialog.askopenfilename(
        parent=parent,
        title=title,
        filetypes=filetypes
    )


def select_save_file(parent: tk.Widget, title: str, filetypes: list, 
                    default_extension: str = None) -> Optional[str]:
    """Show save file dialog."""
    return filedialog.asksaveasfilename(
        parent=parent,
        title=title,
        filetypes=filetypes,
        defaultextension=default_extension
    )