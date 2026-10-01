@echo off
title SiteGuard
cd /d "%~dp0"

echo ========================================
echo  SiteGuard - website security scanner
echo ========================================
echo.

rem --- Find Python without needing it on PATH ---
set PY=
where python >nul 2>nul
if not errorlevel 1 set PY=python
if not defined PY (
  where py >nul 2>nul
  if not errorlevel 1 set PY=py -3
)
if not defined PY (
  for /d %%D in ("%LocalAppData%\Programs\Python\Python3*") do (
    if exist "%%D\python.exe" set "PY=%%D\python.exe"
  )
)

if not defined PY (
  echo  SiteGuard needs Python, and it is not on this computer yet.
  echo.
  echo  I will open the Microsoft Store for you now.
  echo  Click "Get" on Python, wait for it to finish installing,
  echo  then close this window and double-click run.bat again.
  echo.
  pause
  start "" "ms-windows-store://search/?query=Python"
  exit /b 1
)

echo Installing what SiteGuard needs (first run only, then it is instant)...
%PY% -m pip install --quiet flask requests
if errorlevel 1 (
  echo.
  echo  Something went wrong. Check your internet connection,
  echo  then close this window and double-click run.bat again.
  echo.
  pause
  exit /b 1
)

echo.
echo  Starting SiteGuard... your browser will open by itself.
echo.
echo  Keep this window OPEN while you use SiteGuard.
echo  Close this window to stop it.
echo.
start "" /b cmd /c "timeout /t 4 /nobreak >nul & start http://localhost:5050"
%PY% app.py
echo.
pause
