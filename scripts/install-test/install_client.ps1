# Client Installation Script
# This script installs the Platform Client as a Windows service

# Require admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator!"
    Break
}

# Configuration
$serviceName = "PlatformAgent"
$serviceDisplayName = "Platform Agent Service"
$serviceDescription = "Platform Agent Service for remote management"
$pythonPath = "python"  # Assuming Python is in PATH
$scriptPath = Join-Path $PSScriptRoot "client.py"
$logPath = Join-Path $PSScriptRoot "..\logs"
$venvPath = Join-Path $PSScriptRoot "venv"

# Create logs directory if it doesn't exist
if (-not (Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath -Force | Out-Null
}

# Check if Python is installed
try {
    $pythonVersion = & $pythonPath --version
    Write-Host "Found Python: $pythonVersion"
    
    # Get full path to Python executable
    $pythonFullPath = (Get-Command $pythonPath).Source
    Write-Host "Python path: $pythonFullPath"
} catch {
    Write-Error "Python is not installed or not in PATH. Please install Python 3.7 or later."
    exit 1
}

# Create and activate virtual environment
Write-Host "Creating virtual environment..."
& $pythonPath -m venv $venvPath
$venvPythonPath = Join-Path $venvPath "Scripts\python.exe"
$venvPipPath = Join-Path $venvPath "Scripts\pip.exe"

# Install required packages in virtual environment
Write-Host "Installing required packages in virtual environment..."
# Upgrade pip using the correct method
& $venvPythonPath -m pip install --upgrade pip
& $venvPipPath install `
    "requests>=2.31.0" `
    "cryptography>=38.0.0,<39.0.0" `
    "urllib3>=1.25.4,<1.27.0" `
    "charset-normalizer>=2.0.0" `
    "idna>=2.5" `
    "certifi>=2017.4.17" `
    "cffi>=1.14" `
    "pycparser>=2.10"

# Create the service
$serviceExists = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($serviceExists) {
    Write-Host "Service already exists. Stopping and removing..."
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $serviceName
    Start-Sleep -Seconds 2
}

# Create the service using NSSM (Non-Sucking Service Manager)
$nssmPath = Join-Path $PSScriptRoot "nssm.exe"
if (-not (Test-Path $nssmPath)) {
    Write-Host "Downloading NSSM..."
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmZip = Join-Path $env:TEMP "nssm.zip"
    Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip
    Expand-Archive -Path $nssmZip -DestinationPath $env:TEMP -Force
    Copy-Item -Path (Join-Path $env:TEMP "nssm-2.24\win64\nssm.exe") -Destination $nssmPath
    Remove-Item $nssmZip
    Remove-Item (Join-Path $env:TEMP "nssm-2.24") -Recurse -Force
}

# Create a wrapper script to handle paths with spaces and use virtual environment
$wrapperScript = @"
@echo off
cd /d "$PSScriptRoot"
call "$venvPath\Scripts\activate.bat"
"$venvPythonPath" -u "$scriptPath"
"@

$wrapperPath = Join-Path $PSScriptRoot "run_client.bat"
$wrapperScript | Out-File -FilePath $wrapperPath -Encoding ASCII

# Install the service using NSSM
Write-Host "Installing service..."
& $nssmPath install $serviceName $wrapperPath
& $nssmPath set $serviceName DisplayName $serviceDisplayName
& $nssmPath set $serviceName Description $serviceDescription
& $nssmPath set $serviceName AppDirectory $PSScriptRoot
& $nssmPath set $serviceName AppStdout (Join-Path $logPath "service_stdout.log")
& $nssmPath set $serviceName AppStderr (Join-Path $logPath "service_stderr.log")
& $nssmPath set $serviceName Start SERVICE_AUTO_START
& $nssmPath set $serviceName AppRotateFiles 1
& $nssmPath set $serviceName AppRotateOnline 1
& $nssmPath set $serviceName AppRotateSeconds 86400
& $nssmPath set $serviceName AppRotateBytes 10485760

# Set service to run with LocalSystem account
& $nssmPath set $serviceName ObjectName LocalSystem

# Start the service
Write-Host "Starting service..."
try {
    Start-Service -Name $serviceName -ErrorAction Stop
    Write-Host "Service started successfully!"
} catch {
    Write-Error "Failed to start service. Checking logs for details..."
    
    # Check service status
    $service = Get-Service -Name $serviceName
    Write-Host "Service Status: $($service.Status)"
    
    # Check event logs
    $events = Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 
              Where-Object { $_.Message -like "*$serviceName*" }
    
    if ($events) {
        Write-Host "Recent service events:"
        $events | ForEach-Object {
            Write-Host "Time: $($_.TimeGenerated) - Event ID: $($_.EventID) - Message: $($_.Message)"
        }
    }
    
    # Check NSSM logs
    $stdoutLog = Join-Path $logPath "service_stdout.log"
    $stderrLog = Join-Path $logPath "service_stderr.log"
    
    if (Test-Path $stdoutLog) {
        Write-Host "`nService stdout log:"
        Get-Content $stdoutLog -Tail 10
    }
    
    if (Test-Path $stderrLog) {
        Write-Host "`nService stderr log:"
        Get-Content $stderrLog -Tail 10
    }
    
    # Try to start service using sc.exe
    Write-Host "`nAttempting to start service using sc.exe..."
    $result = sc.exe start $serviceName
    Write-Host "sc.exe result: $result"
    
    # Final status check
    Start-Sleep -Seconds 2
    $service = Get-Service -Name $serviceName
    if ($service.Status -eq 'Running') {
        Write-Host "Service is now running!"
    } else {
        Write-Error "Service failed to start. Please check the logs for more details."
        Write-Host "Logs can be found in: $logPath"
    }
}

Write-Host "Installation complete. Logs can be found in: $logPath" 