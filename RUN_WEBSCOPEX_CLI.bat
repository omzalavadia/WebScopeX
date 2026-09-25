@echo off
cd /d "%~dp0"
if "%~1"=="" (echo Usage: RUN_WEBSCOPEX_CLI.bat domain.com [Quick|Standard|Deep] & exit /b 1)
set "PROFILE=%~2"
if "%PROFILE%"=="" set "PROFILE=Standard"
".venv\Scripts\python.exe" webscopex.py --cli --authorized --target "%~1" --profile "%PROFILE%"
