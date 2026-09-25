@echo off
cd /d "%~dp0"
echo Removing local virtual environment and v3.0 Desktop shortcut...
if exist .venv rmdir /s /q .venv
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=[Environment]::GetFolderPath('Desktop')+'\WebScopeX v3.0.lnk'; if(Test-Path $p){Remove-Item $p -Force}" >nul 2>&1
echo Done. Source, SQLite history, workspaces, and reports were left untouched.
pause
