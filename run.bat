@echo off
echo Starting Video Steganography Tool...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    pause
    exit /b 1
)

REM Check if required packages are installed
echo Checking dependencies...
python -c "import cv2, numpy, PIL, cryptography, scipy" >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Run the application
echo Launching Video Steganography Tool...
python main.py

if errorlevel 1 (
    echo.
    echo Application exited with an error.
    pause
)