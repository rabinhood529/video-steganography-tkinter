"""
Video Steganography Application Launcher
Simple launcher script with dependency checking and error handling

Author: AI Assistant
"""

import sys
import subprocess
import importlib
import tkinter as tk
from tkinter import messagebox
import os

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = {
        'cv2': 'opencv-python',
        'numpy': 'numpy',
        'PIL': 'Pillow',
        'docx': 'python-docx',
        'cryptography': 'cryptography'
    }
    
    missing_packages = []
    
    for module, package in required_packages.items():
        try:
            importlib.import_module(module)
            print(f"✓ {package} is installed")
        except ImportError:
            print(f"✗ {package} is missing")
            missing_packages.append(package)
    
    return missing_packages

def install_package(package):
    """Install a package using pip"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        return True
    except subprocess.CalledProcessError:
        return False

def show_installation_guide():
    """Show installation guide in a popup"""
    guide_text = """
Missing Dependencies Detected!

Please install the required packages by running these commands in your terminal:

pip install opencv-python
pip install numpy  
pip install Pillow
pip install python-docx
pip install cryptography

Or install all at once:
pip install -r requirements.txt

After installation, restart this application.
"""
    
    root = tk.Tk()
    root.withdraw()  # Hide main window
    messagebox.showerror("Missing Dependencies", guide_text)
    root.destroy()

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Python Version Error", 
                           f"Python 3.7 or later is required.\n"
                           f"Current version: {sys.version}")
        root.destroy()
        return False
    return True

def check_application_files():
    """Check if all application files exist"""
    required_files = [
        'main.py',
        'video_processor.py', 
        'file_handler.py',
        'steganography_engine.py'
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Missing Files", 
                           f"The following required files are missing:\n\n" +
                           "\n".join(missing_files) +
                           "\n\nPlease ensure all application files are in the same directory.")
        root.destroy()
        return False
    
    return True

def main():
    """Main launcher function"""
    print("Video Steganography Application Launcher")
    print("=" * 45)
    
    # Check Python version
    print("Checking Python version...")
    if not check_python_version():
        return
    
    print(f"✓ Python {sys.version.split()[0]} detected")
    
    # Check application files
    print("\nChecking application files...")
    if not check_application_files():
        return
    
    print("✓ All application files found")
    
    # Check dependencies
    print("\nChecking dependencies...")
    missing_packages = check_dependencies()
    
    if missing_packages:
        print(f"\n✗ Missing packages: {', '.join(missing_packages)}")
        
        # Ask user if they want to auto-install
        root = tk.Tk()
        root.withdraw()
        
        install_choice = messagebox.askyesno(
            "Install Dependencies", 
            f"Missing packages detected:\n{', '.join(missing_packages)}\n\n"
            "Would you like to install them automatically?\n\n"
            "Note: This requires an internet connection."
        )
        
        root.destroy()
        
        if install_choice:
            print("\nInstalling missing packages...")
            success = True
            
            for package in missing_packages:
                print(f"Installing {package}...")
                if install_package(package):
                    print(f"✓ {package} installed successfully")
                else:
                    print(f"✗ Failed to install {package}")
                    success = False
            
            if not success:
                show_installation_guide()
                return
        else:
            show_installation_guide()
            return
    
    print("\n✓ All dependencies satisfied")
    
    # Launch main application
    print("\nLaunching Video Steganography Application...")
    print("Close this window will also close the application.")
    print("=" * 45)
    
    try:
        # Import and run main application
        import main
        main.main()
        
    except ImportError as e:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Import Error", 
                           f"Failed to import main application:\n{str(e)}\n\n"
                           "Please check that all files are in the correct location.")
        root.destroy()
        
    except Exception as e:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Application Error", 
                           f"An error occurred while running the application:\n{str(e)}")
        root.destroy()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nApplication terminated by user.")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        input("Press Enter to exit...")