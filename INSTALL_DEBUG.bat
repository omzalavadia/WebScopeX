@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title WebScopeX v3.0 Installer - DEBUG
color 0E
set "LOG=%~dp0install_log.txt"

echo ====================================================== > "%LOG%"
echo WebScopeX v3.0 Installer Debug Log >> "%LOG%"
echo Started: %date% %time% >> "%LOG%"
echo Folder: %CD% >> "%LOG%"
echo ====================================================== >> "%LOG%"

echo ======================================================
echo       WebScopeX v3.0 - DEBUG INSTALL
echo ======================================================
echo This window stays open on failure.
echo Log: %LOG%
echo.

set "PYEXE="
where py >nul 2>&1
if not errorlevel 1 set "PYEXE=py -3"
if not defined PYEXE (
  where python >nul 2>&1
  if not errorlevel 1 set "PYEXE=python"
)
if not defined PYEXE (
  echo [ERROR] Python not found. >> "%LOG%"
  echo Python not found. Run INSTALL.bat first or install Python 3.11+.
  goto :fail
)

echo [OK] Python: %PYEXE% >> "%LOG%"
%PYEXE% --version >> "%LOG%" 2>&1
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  %PYEXE% -m venv .venv >> "%LOG%" 2>&1
  if errorlevel 1 goto :fail
)

echo Installing dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip >> "%LOG%" 2>&1
if errorlevel 1 goto :fail
".venv\Scripts\python.exe" -m pip install -r requirements.txt >> "%LOG%" 2>&1
if errorlevel 1 goto :fail

echo Validating source...
".venv\Scripts\python.exe" -m py_compile webscopex.py >> "%LOG%" 2>&1
if errorlevel 1 goto :fail

echo [OK] Validation complete. >> "%LOG%"
echo.
echo INSTALLATION / VALIDATION COMPLETE
echo Now run INSTALL.bat once to create all launchers and the Desktop shortcut,
echo or launch directly with:
echo   ".venv\Scripts\python.exe" webscopex.py
echo.
pause
exit /b 0

:fail
echo [ERROR] Installation failed. >> "%LOG%"
echo.
echo INSTALLATION FAILED
echo Open install_log.txt for the exact error.
echo.
pause
exit /b 1
