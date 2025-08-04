# Video Steganography Tool - Setup Guide

## System Requirements

- **Operating System**: Windows 10 (64-bit) or higher
- **Python**: 3.8 or higher
- **RAM**: Minimum 2GB, recommended 4GB+
- **Storage**: At least 1GB free space
- **IDE**: Visual Studio Code (recommended)

## Installation Steps

### 1. Install Python

1. Download Python from [python.org](https://www.python.org/downloads/)
2. **Important**: Check "Add Python to PATH" during installation
3. Verify installation:
   ```cmd
   python --version
   pip --version
   ```

### 2. Install Visual Studio Code

1. Download VS Code from [code.visualstudio.com](https://code.visualstudio.com/)
2. Install the Python extension:
   - Open VS Code
   - Go to Extensions (Ctrl+Shift+X)
   - Search for "Python" and install the Microsoft Python extension

### 3. Download the Project

1. Download or clone the project to your desired location
2. Extract if downloaded as ZIP

### 4. Set Up the Project in VS Code

1. Open VS Code
2. File → Open Folder → Select the project folder
3. Open the integrated terminal (Terminal → New Terminal)

### 5. Create Virtual Environment (Recommended)

```cmd
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate

# On Git Bash:
source venv/Scripts/activate
```

### 6. Install Dependencies

```cmd
pip install -r requirements.txt
```

### 7. Verify Installation

```cmd
python main.py
```

## Troubleshooting

### Common Issues

#### 1. "python is not recognized"
- Python is not in PATH
- Reinstall Python with "Add to PATH" checked
- Or manually add Python to system PATH

#### 2. OpenCV Installation Issues
```cmd
pip uninstall opencv-python
pip install opencv-python==4.8.1.78
```

#### 3. Microsoft Visual C++ Build Tools Required
- Download and install Microsoft C++ Build Tools
- Or install Visual Studio Community with C++ development tools

#### 4. Permission Errors
- Run terminal as Administrator
- Or use `--user` flag: `pip install --user -r requirements.txt`

#### 5. Antivirus Blocking
- Add project folder to antivirus exclusions
- Temporarily disable real-time protection during installation

### Python Version Issues

If you have multiple Python versions:
```cmd
py -3.8 -m pip install -r requirements.txt
py -3.8 main.py
```

### Virtual Environment Issues

If virtual environment doesn't work:
```cmd
# Delete existing venv folder
rmdir /s venv

# Create new one
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## VS Code Configuration

### Recommended Extensions

1. **Python** - Microsoft (Essential)
2. **Python Docstring Generator** - Nils Werner
3. **autoDocstring** - Nils Werner
4. **Python Type Hint** - njqdev

### Workspace Settings

Create `.vscode/settings.json`:
```json
{
    "python.defaultInterpreterPath": "./venv/Scripts/python.exe",
    "python.terminal.activateEnvironment": true,
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "black",
    "files.associations": {
        "*.py": "python"
    }
}
```

### Launch Configuration

Create `.vscode/launch.json`:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Main",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/main.py",
            "console": "integratedTerminal",
            "cwd": "${workspaceFolder}"
        }
    ]
}
```

## Running the Application

### From VS Code
1. Open `main.py`
2. Press F5 or click Run → Start Debugging
3. Or use Ctrl+F5 for Run without Debugging

### From Command Line
```cmd
cd path\to\video-steganography
python main.py
```

### From Virtual Environment
```cmd
cd path\to\video-steganography
venv\Scripts\activate
python main.py
```

## File Structure

```
video-steganography/
├── main.py                 # Main application entry point
├── requirements.txt        # Python dependencies
├── README.md              # Project documentation
├── SETUP.md               # This setup guide
├── gui/                   # GUI components
│   ├── __init__.py
│   ├── main_window.py     # Main GUI window
│   └── components.py      # GUI utilities
├── core/                  # Core functionality
│   ├── __init__.py
│   ├── steganography.py   # Steganography algorithms
│   ├── video_processor.py # Video processing
│   └── encryption.py      # Encryption/decryption
├── utils/                 # Utility functions
│   ├── __init__.py
│   ├── file_handler.py    # File operations
│   └── logger.py          # Logging configuration
├── logs/                  # Application logs (created automatically)
├── temp/                  # Temporary files (created automatically)
└── output/                # Output files (created automatically)
```

## Performance Tips

### For Large Videos

1. **Increase Virtual Memory**:
   - System Properties → Advanced → Performance Settings
   - Advanced → Virtual Memory → Change
   - Set custom size (Initial: 4GB, Maximum: 8GB)

2. **Close Unnecessary Applications**:
   - Free up RAM before processing large videos

3. **Use SSD Storage**:
   - Store videos on SSD for faster processing

### Memory Management

- Process videos under 50MB as specified
- Use LSB algorithm for faster processing
- DCT algorithm is slower but more secure

## Security Considerations

1. **Antivirus**: May flag encrypted files as suspicious
2. **Firewall**: No network access required
3. **Privacy**: All processing is local, no data sent online
4. **Passwords**: Use strong passwords for encryption

## Getting Help

1. Check the logs in the `logs/` directory
2. Enable debug logging in `utils/logger.py`
3. Check GitHub issues (if applicable)
4. Ensure all dependencies are correctly installed

## Development Mode

For development and debugging:

```cmd
# Install development dependencies
pip install pylint black pytest

# Run tests (if available)
pytest

# Format code
black .

# Lint code
pylint core/ gui/ utils/ main.py
```

## Uninstallation

1. Delete the project folder
2. Remove virtual environment: `rmdir /s venv`
3. Optionally uninstall Python packages:
   ```cmd
   pip uninstall -r requirements.txt -y
   ```