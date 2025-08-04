@echo off
title Video Steganography Tool

echo ============================================
echo Video Steganography Tool v1.0
echo ============================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo Virtual environment not found. Using system Python...
)

REM Check if requirements are installed
echo Checking dependencies...
python -c "import cv2, numpy, PIL, cryptography, scipy, docx" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        echo Please run: pip install -r requirements.txt
        pause
        exit /b 1
    )
)

echo Starting Video Steganography Tool...
echo.
python main.py

if errorlevel 1 (
    echo.
    echo Application exited with an error.
    echo Check the logs directory for more information.
    pause
)

echo.
echo Application closed.
pause