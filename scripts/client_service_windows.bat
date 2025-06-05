@echo off
setlocal
set AGENT_DIR=%ProgramFiles%\PlatformAgent
set SERVICE_NAME=PlatformAgent

REM Create agent directory
if not exist "%AGENT_DIR%" mkdir "%AGENT_DIR%"
copy /Y "%~dp0client.py" "%AGENT_DIR%\client.py"
copy /Y "%~dp0client_config.json" "%AGENT_DIR%\client_config.json"

REM Install service using NSSM (https://nssm.cc/)
set NSSM_EXE=nssm.exe
where %NSSM_EXE% >nul 2>nul || (
  echo Please download nssm.exe and place it in your PATH.
  exit /b 1
)

REM Register the service
%nssm_exe% install %SERVICE_NAME% python "%AGENT_DIR%\client.py"

REM Set service to auto start
%nssm_exe% set %SERVICE_NAME% Start SERVICE_AUTO_START

REM Start the service
net start %SERVICE_NAME%

echo Agent installed and running as service: %SERVICE_NAME%
endlocal 