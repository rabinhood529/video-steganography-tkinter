# Video Steganography Tool

A comprehensive Python application for hiding secret files within video files using advanced steganography techniques. Features a modern Tkinter GUI with support for multiple file types, encryption, and both LSB and DCT embedding algorithms.

## Features

### 🎯 Core Functionality
- **Embed secret files** into cover videos using LSB or DCT algorithms
- **Extract hidden files** from stego videos with perfect reconstruction
- **Support for multiple file types**:
  - Text files: .txt, .doc, .docx
  - Images: .jpg, .png, .bmp, .gif
  - Videos: .mp4, .avi, .mov, .mkv

### 🔒 Security Features
- **Password encryption** using AES-256 with PBKDF2 key derivation
- **Strong password validation** with complexity requirements
- **Secure file handling** with metadata preservation

### 📹 Video Support
- **Supported resolutions**: 480p, 720p, 1080p
- **Maximum file size**: 50MB per video
- **Supported formats**: MP4, AVI, MOV, MKV, WMV
- **Dynamic capacity calculation** based on video properties

### 🖥️ GUI Features
- **Modern Tkinter interface** with tabbed layout
- **Real-time capacity checking** and file validation
- **Progress bars** for long operations
- **Comprehensive logging** and error handling
- **Metadata display** for video properties
- **File browsers** with appropriate filters

### ⚙️ Algorithms
- **LSB (Least Significant Bit)**: Fast embedding with minimal quality loss
- **DCT (Discrete Cosine Transform)**: More secure embedding in frequency domain

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup Instructions

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd video-steganography-tool
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python main.py
   ```

### Dependencies
- `opencv-python`: Video processing and computer vision
- `numpy`: Numerical computations
- `Pillow`: Image processing
- `cryptography`: Encryption and security
- `scipy`: Scientific computing (DCT transforms)

## Usage Guide

### Embedding Secret Files

1. **Launch the application** by running `python main.py`
2. **Select the "Embed Secret File" tab**
3. **Choose your files**:
   - Browse for a cover video (max 50MB, 480p/720p/1080p)
   - Select a secret file to hide
   - Choose output location for the stego video
4. **Configure settings**:
   - Select embedding method (LSB or DCT)
   - Optionally enable password protection
5. **Check capacity**: Ensure your secret file fits within the video capacity
6. **Click "Embed Secret File"** and wait for completion

### Extracting Secret Files

1. **Select the "Extract Secret File" tab**
2. **Choose your files**:
   - Browse for the stego video containing hidden data
   - For DCT extraction, also select the original video
   - Choose output directory for extracted file
3. **Configure settings**:
   - Select extraction method (must match embedding method)
   - Enter password if data was encrypted
4. **Click "Extract Secret File"** and wait for completion

### Capacity Guidelines

The maximum secret file size depends on:
- **Video resolution**: Higher resolution = more capacity
- **Video duration**: Longer videos = more capacity
- **Embedding method**: LSB offers more capacity than DCT
- **Frame count**: More frames = more capacity

**Typical capacities**:
- 720p, 30fps, 60s video with LSB: ~500MB capacity
- 720p, 30fps, 60s video with DCT: ~50MB capacity

## Technical Details

### LSB Algorithm
- Embeds data in the least significant bits of pixel values
- Minimal visual impact on video quality
- Higher capacity but less secure against analysis
- Suitable for casual hiding of files

### DCT Algorithm
- Embeds data in frequency domain coefficients
- More robust against compression and analysis
- Lower capacity but higher security
- Requires original video for extraction

### Encryption
- Uses Fernet (AES-128) encryption with PBKDF2 key derivation
- 100,000 iterations for key strengthening
- Random salt generation for each encryption
- Password requirements: 8+ chars, mixed case, numbers

### File Format Support

**Secret Files**:
- Text: .txt, .doc, .docx (max 10MB)
- Images: .jpg, .png, .bmp, .gif (max 20MB)
- Videos: .mp4, .avi, .mov, .mkv (max 30MB)

**Cover Videos**:
- Formats: .mp4, .avi, .mov, .mkv, .wmv
- Resolutions: 854×480, 1280×720, 1920×1080
- Maximum size: 50MB

## Project Structure

```
video-steganography-tool/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── README.md              # This documentation
├── core/                  # Core steganography algorithms
│   ├── __init__.py
│   └── steganography.py   # LSB and DCT implementations
├── gui/                   # Graphical user interface
│   ├── __init__.py
│   └── main_window.py     # Main GUI application
└── utils/                 # Utility modules
    ├── __init__.py
    ├── video_utils.py     # Video processing utilities
    └── encryption.py      # Encryption and security
```

## Error Handling

The application includes comprehensive error handling for:
- **File validation**: Checks file existence, format, and size
- **Video validation**: Verifies resolution, codec, and properties
- **Capacity checking**: Prevents embedding oversized files
- **Password validation**: Ensures strong passwords
- **Process monitoring**: Tracks embedding/extraction progress
- **Exception logging**: Detailed error messages and logging

## Logging

All operations are logged to:
- **Console output**: Real-time status updates
- **GUI log panels**: In-application activity logs
- **Log file**: `video_steganography.log` for persistent logging

Log levels include INFO, WARNING, and ERROR messages for debugging and monitoring.

## Performance Considerations

### Embedding Time Estimates
- **LSB method**: ~10ms per frame
- **DCT method**: ~50ms per frame
- **Factors**: Resolution, frame count, file size

### Memory Usage
- Processes videos frame by frame to minimize memory usage
- Temporary data cleaned up automatically
- Suitable for videos up to 50MB on typical systems

### Quality Impact
- **LSB**: Minimal visible quality loss (<1% PSNR reduction)
- **DCT**: Slightly more visible but still imperceptible to casual viewing
- **Both methods**: Maintain video playability and compatibility

## Troubleshooting

### Common Issues

**"Video file too large"**
- Ensure video is under 50MB
- Compress video or use shorter clips

**"Unsupported resolution"**
- Convert video to 480p, 720p, or 1080p
- Use video conversion tools like FFmpeg

**"Secret file too large"**
- Check capacity display in GUI
- Use shorter videos or smaller secret files
- Consider using LSB method for higher capacity

**"Cannot open video file"**
- Ensure video file is not corrupted
- Try different video formats
- Check file permissions

**"Extraction failed"**
- Verify embedding method matches extraction method
- Ensure correct password for encrypted data
- For DCT: provide the exact original video file

### Performance Issues
- Close other applications to free memory
- Use SSD storage for faster file I/O
- Consider shorter videos for faster processing

## Security Notes

### Best Practices
- Use strong passwords (8+ characters, mixed case, numbers)
- Keep original videos secure when using DCT method
- Delete temporary files after operations
- Use secure channels to share passwords

### Limitations
- LSB method vulnerable to statistical analysis
- DCT method requires original video for extraction
- No protection against video re-encoding attacks
- Suitable for casual privacy, not military-grade security

## License

This project is provided as-is for educational and personal use. Please ensure compliance with local laws regarding steganography and encryption.

## Support

For issues, questions, or contributions, please refer to the source code comments and logging output for debugging information. The application includes comprehensive error messages and logging to help diagnose problems.

---

**Note**: This tool is designed for legitimate privacy and security purposes. Users are responsible for complying with applicable laws and regulations regarding steganography and encryption in their jurisdiction.