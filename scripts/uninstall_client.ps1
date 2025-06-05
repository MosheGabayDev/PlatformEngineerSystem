# Client Uninstallation Script
# This script removes the Platform Client service and its components

# Require admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator!"
    Break
}

# Configuration
$serviceName = "PlatformAgent"
$scriptPath = Join-Path $PSScriptRoot "client.py"
$logPath = Join-Path $PSScriptRoot "..\logs"
$venvPath = Join-Path $PSScriptRoot "venv"

# Stop and remove the service
$serviceExists = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($serviceExists) {
    Write-Host "Stopping service..."
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    Write-Host "Removing service..."
    sc.exe delete $serviceName
    Start-Sleep -Seconds 2
}

# Remove the wrapper script
$wrapperPath = Join-Path $PSScriptRoot "run_client.bat"
if (Test-Path $wrapperPath) {
    Write-Host "Removing wrapper script..."
    Remove-Item $wrapperPath -Force
}

# Remove NSSM
$nssmPath = Join-Path $PSScriptRoot "nssm.exe"
if (Test-Path $nssmPath) {
    Write-Host "Removing NSSM..."
    Remove-Item $nssmPath -Force
}

# Remove virtual environment
if (Test-Path $venvPath) {
    Write-Host "Removing virtual environment..."
    Remove-Item -Path $venvPath -Recurse -Force
}

# Remove logs
if (Test-Path $logPath) {
    Write-Host "Removing logs..."
    Remove-Item -Path $logPath -Recurse -Force
}

# Remove client configuration
$configFile = Join-Path $PSScriptRoot "client_config.json"
if (Test-Path $configFile) {
    Write-Host "Removing client configuration..."
    Remove-Item $configFile -Force
}

# Remove server public key
$publicKeyFile = Join-Path $PSScriptRoot "server_public_key.pem"
if (Test-Path $publicKeyFile) {
    Write-Host "Removing server public key..."
    Remove-Item $publicKeyFile -Force
}

Write-Host "Uninstallation complete!" 