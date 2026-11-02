@echo off
cd /d "%~dp0"
echo Installing SentinelXT dependencies for Python 3.8...
python -m pip install -r requirements-win7.txt
if errorlevel 1 (
  echo.
  echo Installation failed. Check the first pip error above.
  pause
  exit /b 1
)
echo.
echo Dependencies installed.
echo Run check_environment.bat to verify modules and compile local YARA rules.
pause
