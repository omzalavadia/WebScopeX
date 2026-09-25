@echo off
cd /d "%~dp0"
".venv\Scripts\python.exe" webscopex.py
if errorlevel 1 pause
