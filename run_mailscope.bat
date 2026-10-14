@echo off
REM ============================================================
REM  MailScope launcher for Windows
REM  Double-click to start. First run creates a virtual
REM  environment and installs dependencies (needs internet once).
REM  Optional: run_mailscope.bat 8080   -> use another port
REM ============================================================
setlocal EnableExtensions
cd /d "%~dp0"
title MailScope
chcp 65001 >nul

set "PORT=5000"
if not "%~1"=="" set "PORT=%~1"
set "HOST=127.0.0.1"
set "URL=http://%HOST%:%PORT%"
set "VPY=.venv\Scripts\python.exe"

REM ---- Make sure the project files are complete -------------
if not exist "mailscope_core\__init__.py" goto files_missing
if not exist "app.py" goto files_missing

REM ---- Already running? Just open the browser ----------------
netstat -ano | findstr /R /C:":%PORT% .*LISTENING" >nul 2>&1
if not errorlevel 1 goto already_running

REM ---- Find Python 3.9+ ---------------------------------------
if exist "%VPY%" goto have_venv

set "PY=py -3"
py -3 --version >nul 2>&1
if not errorlevel 1 goto found_python
set "PY=python"
python --version >nul 2>&1
if errorlevel 1 goto no_python

:found_python
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
if errorlevel 1 goto old_python

echo [MailScope] Creating virtual environment in .venv ...
%PY% -m venv .venv
if errorlevel 1 goto venv_failed

:have_venv
REM ---- Install / update dependencies when requirements change -
fc /b requirements.txt .venv\requirements.installed >nul 2>&1
if not errorlevel 1 goto deps_ok
echo [MailScope] Installing dependencies ...
"%VPY%" -m pip install --upgrade pip --quiet --disable-pip-version-check
"%VPY%" -m pip install -r requirements.txt --disable-pip-version-check
if errorlevel 1 goto pip_failed
copy /y requirements.txt .venv\requirements.installed >nul

:deps_ok
REM ---- Sample emails for a first try --------------------------
if not exist "samples\phishing_sample.eml" "%VPY%" samples\make_samples.py >nul 2>&1

REM ---- Open the browser once the server is up -----------------
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process '%URL%'"

echo.
echo  ============================================
echo    MailScope running at %URL%
echo    Close this window or press Ctrl+C to stop.
echo  ============================================
echo.
"%VPY%" app.py
echo.
echo [MailScope] Server stopped.
pause
exit /b 0

REM ---- Messages -----------------------------------------------
:already_running
echo [MailScope] Something is already listening on port %PORT% - opening %URL%
echo             If that is not MailScope, run: run_mailscope.bat 5050
start "" "%URL%"
timeout /t 4 >nul
exit /b 0

:files_missing
echo [MailScope] Project files are missing in %CD%
echo   Expected app.py and the mailscope_core folder next to this .bat file.
echo   Extract the complete mailscope.zip into an empty folder and run it from there.
pause
exit /b 1

:no_python
echo [MailScope] Python was not found.
echo   Install Python 3.9 or newer from https://www.python.org/downloads/
echo   and tick "Add python.exe to PATH" during setup, then run this file again.
pause
exit /b 1

:old_python
echo [MailScope] Python 3.9 or newer is required. Found:
%PY% --version
pause
exit /b 1

:venv_failed
echo [MailScope] Could not create the virtual environment.
pause
exit /b 1

:pip_failed
echo [MailScope] Dependency installation failed - check your internet / proxy and try again.
echo   Behind a corporate proxy:  set HTTPS_PROXY=http://proxy:port  before running.
pause
exit /b 1
