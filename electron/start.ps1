Set-Location "$PSScriptRoot\.."
$backend = Join-Path $PSScriptRoot "..\backend"
$frontend = Join-Path $PSScriptRoot "..\sceu_system"

Write-Host "Building frontend..."
Set-Location $frontend
npm run build

Write-Host "Starting Electron app..."
Set-Location "$PSScriptRoot"
npm start
