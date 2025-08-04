#!/bin/bash

echo "Starting Video Steganography Tool..."
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "ERROR: Python is not installed"
        echo "Please install Python 3.8 or higher"
        exit 1
    fi
    PYTHON_CMD="python"
else
    PYTHON_CMD="python3"
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "ERROR: Python $REQUIRED_VERSION or higher is required"
    echo "Current version: $PYTHON_VERSION"
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    if ! command -v pip &> /dev/null; then
        echo "ERROR: pip is not installed"
        echo "Please install pip to manage Python packages"
        exit 1
    fi
    PIP_CMD="pip"
else
    PIP_CMD="pip3"
fi

# Check if required packages are installed
echo "Checking dependencies..."
$PYTHON_CMD -c "import cv2, numpy, PIL, cryptography, scipy" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing required packages..."
    $PIP_CMD install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
fi

# Make sure the script has execute permissions
chmod +x "$0"

# Run the application
echo "Launching Video Steganography Tool..."
$PYTHON_CMD main.py

if [ $? -ne 0 ]; then
    echo
    echo "Application exited with an error."
    read -p "Press Enter to continue..."
fi