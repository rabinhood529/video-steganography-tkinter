# Video Steganography Tool - Usage Examples

## Quick Start Guide

### 1. Basic File Embedding

**Scenario**: Hide a secret text file in a video

1. **Launch the application**:
   ```cmd
   python main.py
   ```

2. **Select Cover Video**:
   - Click "Select Cover Video"
   - Choose a video file (.mp4 or .avi, max 50MB)
   - Supported resolutions: 480p, 720p, 1080p

3. **Select Secret File**:
   - Click "Select Secret File"
   - Choose your secret file (.txt, .doc, .docx, .jpg, .png, .mp4, .avi)

4. **Calculate Capacity**:
   - Click "Calculate Capacity" to see how much data you can embed
   - Check if your secret file fits within the capacity

5. **Choose Options**:
   - Algorithm: LSB (faster) or DCT (more secure)
   - Optional: Check "Use password encryption" for extra security

6. **Embed File**:
   - Click "Embed File"
   - Choose where to save the output video
   - Wait for the process to complete

### 2. Basic File Extraction

**Scenario**: Extract a hidden file from a stego video

1. **Switch to Extract Tab**:
   - Click the "Extract File" tab

2. **Select Stego Video**:
   - Click "Select Stego Video"
   - Choose the video containing hidden data

3. **Set Options**:
   - Choose the same algorithm used for embedding
   - Check password option if the file was encrypted

4. **Extract File**:
   - Click "Extract File"
   - Choose output location
   - Enter password if required
   - Wait for extraction to complete

## Advanced Examples

### Example 1: Hiding Sensitive Documents

**Use Case**: Hide confidential business documents in a presentation video

**Files**:
- Cover video: `presentation.mp4` (720p, 30MB)
- Secret file: `confidential_report.docx` (2MB)

**Steps**:
1. Select both files in the application
2. Calculate capacity - should show plenty of space available
3. Enable password encryption with a strong password
4. Choose DCT algorithm for better security
5. Save as `presentation_with_data.mp4`

**Security Benefits**:
- DCT algorithm makes detection harder
- Password encryption protects content
- Video appears normal when played

### Example 2: Hiding Multiple Small Files

**Use Case**: Hide several small images in a vacation video

**Approach**: Combine files into a ZIP archive first

**Steps**:
1. Create ZIP file containing all images:
   ```cmd
   # Using built-in Windows compression
   Right-click files → Send to → Compressed folder
   ```
2. Use the ZIP file as your secret file
3. Embed using LSB algorithm (faster for larger files)
4. During extraction, you'll get the ZIP file back
5. Extract the ZIP to recover all original files

### Example 3: Text Message Hiding

**Use Case**: Hide a secret message in a social media video

**Files**:
- Cover video: `vacation_clip.mp4` (480p, 10MB)
- Secret file: `secret_message.txt` (1KB)

**Best Practices**:
1. Use LSB algorithm (sufficient for text)
2. No password needed for simple messages
3. Keep the message file small
4. Test the output video plays normally

### Example 4: Backup Important Files

**Use Case**: Create a backup of important files disguised as a regular video

**Strategy**:
1. Create a ZIP archive of important files
2. Use a large, boring video as cover (like a lecture recording)
3. Use DCT algorithm with strong password
4. Store the stego video in cloud storage
5. Only you know it contains hidden data

## Algorithm Comparison

### LSB (Least Significant Bit)

**Best For**:
- Large files (images, videos)
- Fast processing needed
- Less critical security requirements

**Characteristics**:
- Faster embedding/extraction
- Higher capacity
- Easier to detect with analysis tools
- Minimal video quality impact

**Example Capacity** (720p, 30fps, 10 seconds):
- Approximately 2-5MB of hidden data

### DCT (Discrete Cosine Transform)

**Best For**:
- Sensitive documents
- High security requirements
- Smaller files

**Characteristics**:
- Slower processing
- Lower capacity
- Harder to detect
- Slightly more video quality impact

**Example Capacity** (720p, 30fps, 10 seconds):
- Approximately 500KB-1MB of hidden data

## Security Best Practices

### Password Guidelines

1. **Strong Passwords**:
   - Minimum 12 characters
   - Mix of letters, numbers, symbols
   - Avoid dictionary words
   - Example: `My$ecr3t!Vid30#2024`

2. **Password Storage**:
   - Use a password manager
   - Don't store passwords with stego videos
   - Consider using memorable passphrases

### Operational Security

1. **File Management**:
   - Delete original secret files after embedding
   - Use secure deletion tools if necessary
   - Don't keep obvious backups

2. **Video Selection**:
   - Use natural-looking cover videos
   - Avoid videos that might be analyzed
   - Consider the context where you'll share them

3. **Testing**:
   - Always test extraction before deleting originals
   - Verify file integrity after extraction
   - Test with different video players

## Troubleshooting Common Issues

### Capacity Problems

**Issue**: "Secret file too large" error

**Solutions**:
1. Compress the secret file (ZIP, RAR)
2. Use a larger cover video
3. Switch to LSB algorithm (higher capacity)
4. Split large files into smaller parts

### Quality Issues

**Issue**: Output video has visible artifacts

**Solutions**:
1. Use LSB algorithm (less quality impact)
2. Choose a higher quality source video
3. Reduce secret file size
4. Test with different video formats

### Extraction Failures

**Issue**: Cannot extract hidden file

**Possible Causes**:
1. Wrong algorithm selected
2. Incorrect password
3. Video was compressed/re-encoded
4. Original embedding failed

**Solutions**:
1. Try both LSB and DCT algorithms
2. Verify password spelling/case
3. Use original stego video file
4. Check application logs for errors

## Performance Optimization

### For Large Videos

1. **System Preparation**:
   - Close unnecessary applications
   - Ensure sufficient RAM (4GB+ recommended)
   - Use SSD storage for faster I/O

2. **Processing Tips**:
   - Process during low system usage
   - Don't interrupt the process
   - Monitor system resources

### Memory Management

**Video Size Guidelines**:
- 480p: Up to 50MB (as specified)
- 720p: Up to 40MB recommended
- 1080p: Up to 30MB recommended

**If You Exceed Limits**:
1. Compress the video first
2. Trim unnecessary parts
3. Reduce video quality/bitrate
4. Use video editing software to optimize

## File Format Considerations

### Supported Secret Files

| Format | Extension | Notes |
|--------|-----------|-------|
| Text | .txt | Plain text files |
| Word | .doc, .docx | Microsoft Word documents |
| Images | .jpg, .jpeg, .png | Common image formats |
| Videos | .mp4, .avi | Small video files |

### Cover Video Requirements

- **Formats**: MP4, AVI
- **Max Size**: 50MB
- **Resolutions**: 480p, 720p, 1080p
- **Codecs**: Most common codecs supported

## Legal and Ethical Considerations

### Legitimate Uses

- Personal file backup
- Secure document storage
- Digital watermarking
- Research and education
- Privacy protection

### Important Notes

- Respect copyright laws
- Don't use for illegal activities
- Be aware of local regulations
- Consider the rights of others
- Use responsibly

## Advanced Tips

### Batch Processing

For multiple files, consider:
1. Creating a script to automate the process
2. Using the command-line interface (if available)
3. Processing files in sequence

### Integration with Other Tools

- **File Compression**: 7-Zip, WinRAR
- **Video Editing**: FFmpeg, HandBrake
- **Security**: VeraCrypt for additional encryption

### Verification

Always verify your embedded files:
1. Extract immediately after embedding
2. Compare file sizes and checksums
3. Test file functionality
4. Keep verification logs

This ensures your steganography process is working correctly and your data is safe.