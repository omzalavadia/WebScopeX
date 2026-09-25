@echo off
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: MIGRATE_LEGACY_HISTORY.bat "C:\path\to\old\project"
  pause
  exit /b 1
)
if not exist "%~1\webenum_history.db" (
  echo No legacy webenum_history.db found in: %~1
  pause
  exit /b 1
)
if exist "webscopex_history.db" (
  echo A v3 history database already exists. Back it up or remove it before migration.
  pause
  exit /b 1
)
copy "%~1\webenum_history.db" "webscopex_history.db"
echo Migration complete. Workspaces and scan history were copied.
pause
