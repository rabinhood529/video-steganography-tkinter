# Video Steganography Project

A comprehensive Python application for hiding and extracting secret files within video files using steganography techniques.

## Features

- **File Support**: Hide text files (.txt, .doc, .docx), images (.jpg, .png), and videos (.mp4, .avi) within cover videos
- **Video Formats**: Support for 480p, 720p, and 1080p resolution videos (max 50MB)
- **Algorithms**: LSB (Least Significant Bit) and DCT (Discrete Cosine Transform) steganography
- **Encryption**: Optional password-based encryption for secret files
- **GUI**: User-friendly Tkinter interface with progress tracking and error handling
- **Capacity Calculation**: Dynamic calculation of maximum embeddable file size based on video properties

## Requirements

- Python 3.8 or higher
- Windows 10 (tested) / Linux / macOS
- At least 2GB RAM for processing large videos

## Installation

1. **Clone or download the project**
2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

## Usage

### Embedding a Secret File
1. Launch the application
2. Click "Select Cover Video" and choose your video file
3. Click "Select Secret File" and choose the file to hide
4. (Optional) Set a password for encryption
5. Choose embedding algorithm (LSB or DCT)
6. Click "Embed File" to hide the secret file
7. Save the output video

### Extracting a Secret File
1. Launch the application
2. Click "Select Video with Hidden Data"
3. (Optional) Enter password if the file was encrypted
4. Choose the extraction algorithm
5. Click "Extract File" to retrieve the hidden file
6. Save the extracted file

## Technical Details

### Supported File Types
- **Secret Files**: .txt, .doc, .docx, .jpg, .png, .mp4, .avi
- **Cover Videos**: .mp4, .avi (480p/720p/1080p, max 50MB)

### Algorithms
- **LSB**: Modifies least significant bits of video frames
- **DCT**: Uses discrete cosine transform coefficients for embedding

### Security
- AES-256 encryption for secret files
- Password-based key derivation (PBKDF2)

## Project Structure

```
video-steganography/
├── main.py                 # Main application entry point
├── gui/
│   ├── __init__.py
│   ├── main_window.py      # Main GUI window
│   └── components.py       # GUI components and utilities
├── core/
│   ├── __init__.py
│   ├── steganography.py    # Core steganography algorithms
│   ├── video_processor.py  # Video processing utilities
│   └── encryption.py       # Encryption/decryption functionality
├── utils/
│   ├── __init__.py
│   ├── file_handler.py     # File operations and validation
│   └── logger.py           # Logging configuration
├── requirements.txt
└── README.md
```

## Troubleshooting

- **OpenCV Issues**: Ensure proper OpenCV installation with `pip install opencv-python`
- **Memory Errors**: Use smaller video files or increase system RAM
- **File Format Errors**: Verify file formats are supported

## License

This project is for educational purposes. Please respect copyright laws when using steganography techniques.