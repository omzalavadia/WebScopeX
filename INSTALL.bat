@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title WebScopeX v3.0 Installer
color 0A

echo ======================================================
echo          WebScopeX v3.0 Installer
echo ======================================================
echo.
echo Authorized security assessment toolkit.
echo.

set "PYEXE="
where py >nul 2>&1
if not errorlevel 1 set "PYEXE=py -3"
if not defined PYEXE (
    where python >nul 2>&1
    if not errorlevel 1 set "PYEXE=python"
)

if not defined PYEXE (
    echo Python was not found.
    where winget >nul 2>&1
    if errorlevel 1 (
        echo Install Python 3.11 or newer and run this installer again.
        pause
        exit /b 1
    )
    echo Installing Python 3.12 with winget...
    winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo Python installation failed.
        pause
        exit /b 1
    )
    if exist "%LocalAppData%\Programs\Python\Python312\python.exe" set "PYEXE=%LocalAppData%\Programs\Python\Python312\python.exe"
    if not defined PYEXE if exist "%ProgramFiles%\Python312\python.exe" set "PYEXE=%ProgramFiles%\Python312\python.exe"
)

if not defined PYEXE (
    echo Python was installed but is not visible yet. Close this window and run INSTALL.bat again.
    pause
    exit /b 1
)

echo Using Python: %PYEXE%
%PYEXE% --version
if errorlevel 1 goto :fail

if not exist ".venv\Scripts\python.exe" (
    echo.
    echo Creating isolated Python environment...
    %PYEXE% -m venv .venv
    if errorlevel 1 goto :fail
)

echo.
echo Installing dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :fail
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :fail

echo.
echo Validating application...
".venv\Scripts\python.exe" -m py_compile webscopex.py
if errorlevel 1 goto :fail

>RUN_WEBSCOPEX.bat echo @echo off
>>RUN_WEBSCOPEX.bat echo cd /d "%%~dp0"
>>RUN_WEBSCOPEX.bat echo start "" ".venv\Scripts\pythonw.exe" webscopex.py

>RUN_WEBSCOPEX_DEBUG.bat echo @echo off
>>RUN_WEBSCOPEX_DEBUG.bat echo cd /d "%%~dp0"
>>RUN_WEBSCOPEX_DEBUG.bat echo ".venv\Scripts\python.exe" webscopex.py
>>RUN_WEBSCOPEX_DEBUG.bat echo if errorlevel 1 pause

>RUN_WEBSCOPEX_CLI.bat echo @echo off
>>RUN_WEBSCOPEX_CLI.bat echo cd /d "%%~dp0"
>>RUN_WEBSCOPEX_CLI.bat echo if "%%~1"=="" ^(echo Usage: RUN_WEBSCOPEX_CLI.bat domain.com [Quick^|Standard^|Deep] ^& exit /b 1^)
>>RUN_WEBSCOPEX_CLI.bat echo set "PROFILE=%%~2"
>>RUN_WEBSCOPEX_CLI.bat echo if "%%PROFILE%%"=="" set "PROFILE=Standard"
>>RUN_WEBSCOPEX_CLI.bat echo ".venv\Scripts\python.exe" webscopex.py --cli --authorized --target "%%~1" --profile "%%PROFILE%%"

>RUN_TOOL_STATUS.bat echo @echo off
>>RUN_TOOL_STATUS.bat echo cd /d "%%~dp0"
>>RUN_TOOL_STATUS.bat echo ".venv\Scripts\python.exe" webscopex.py --list-tools
>>RUN_TOOL_STATUS.bat echo pause

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws=New-Object -ComObject WScript.Shell; $s=$ws.CreateShortcut([Environment]::GetFolderPath('Desktop')+'\WebScopeX v3.0.lnk'); $s.TargetPath='%~dp0RUN_WEBSCOPEX.bat'; $s.WorkingDirectory='%~dp0'; $s.IconLocation=$env:SystemRoot+'\System32\shell32.dll,23'; $s.Save()" >nul 2>&1

echo.
echo ======================================================
echo Installation complete.
echo ======================================================
echo First launch: RUN_WEBSCOPEX_DEBUG.bat
echo CLI example: RUN_WEBSCOPEX_CLI.bat example.com Standard
echo Optional integrations: open Tool Status inside the GUI.
echo.
pause
exit /b 0

:fail
echo.
echo Installation failed. Keep this window open and copy the error above.
pause
exit /b 1
