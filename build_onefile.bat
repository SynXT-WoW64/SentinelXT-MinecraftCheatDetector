@echo off
cd /d "%~dp0"
echo Building SentinelXT 0.1.4 Build #6 (single EXE)...
python -m PyInstaller --noconfirm --clean --windowed --onefile --name SentinelXT-build6 --icon "assets\sentinelxt.ico" --add-data "assets;assets" --add-data "database;database" main.py
if errorlevel 1 (
  echo.
  echo BUILD FAILED. Read the error above.
  pause
  exit /b 1
)
echo.
echo Build complete: dist\SentinelXT-build6.exe
pause
