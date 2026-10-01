@echo off
title SiteGuard
echo ========================================
echo  SiteGuard - website security scanner
echo ========================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo [X] Python is not installed on this computer.
  echo.
  echo  Get it free from https://www.python.org/downloads/
  echo  IMPORTANT: during install, tick the box
  echo  "Add python.exe to PATH" at the bottom.
  echo.
  pause
  exit /b 1
)

echo Installing what SiteGuard needs (first run only, then it is instant)...
python -m pip install --quiet flask requests
echo.
echo Starting SiteGuard...
echo.
echo  Open this in your browser:  http://localhost:5050
echo.
echo  Keep this window OPEN while you use SiteGuard.
echo  Close this window to stop it.
echo.
python app.py
echo.
pause
