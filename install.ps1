#Requires -Version 5.1
<#
.SYNOPSIS
    Nethawk installer for Windows
.DESCRIPTION
    Downloads Nethawk.exe from GitHub and adds it to your user PATH.
.EXAMPLE
    irm https://raw.githubusercontent.com/master-sauce/Nethawk/main/install.ps1 | iex
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Repo       = "master-sauce/Nethawk"
$BinaryName = "nethawk"
$ExeName    = "Nethawk.exe"
$RawBase    = "https://raw.githubusercontent.com/$Repo/main"
$InstallDir = Join-Path $env:USERPROFILE ".local\bin\nethawk"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Info    { param($msg) Write-Host "[nethawk] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[nethawk] $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[nethawk] $msg" -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "[nethawk] ERROR: $msg" -ForegroundColor Red; exit 1 }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Nethawk Installer" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# ── Create install directory ──────────────────────────────────────────────────
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Info "Created install directory: $InstallDir"
}

# ── Download binary ───────────────────────────────────────────────────────────
$DownloadUrl  = "$RawBase/$ExeName"
$Destination  = Join-Path $InstallDir "$BinaryName.exe"

Write-Info "Downloading $ExeName from GitHub..."
Write-Info "URL: $DownloadUrl"

try {
    $ProgressPreference = 'SilentlyContinue'   # speeds up Invoke-WebRequest significantly
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $Destination -UseBasicParsing
    Write-Success "Downloaded to: $Destination"
} catch {
    # Fallback: try go install if Go is available
    Write-Warn "Direct download failed. Trying 'go install' as fallback..."
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Info "Running: go install github.com/$Repo@latest"
        go install "github.com/${Repo}@latest"
        $GoPath = (go env GOPATH)
        $GoInstallDir = Join-Path $GoPath "bin"
        Write-Success "Installed via 'go install' to: $GoInstallDir"
        $InstallDir = $GoInstallDir
    } else {
        Write-Fail "Download failed and Go is not installed.`nInstall Go from https://go.dev/dl/ and retry, or check your internet connection."
    }
}

# ── Add to user PATH ──────────────────────────────────────────────────────────
Write-Info "Checking PATH..."

$CurrentPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
$PathEntries = $CurrentPath -split ";" | Where-Object { $_ -ne "" }

if ($PathEntries -contains $InstallDir) {
    Write-Warn "$InstallDir is already in your PATH. Skipping."
} else {
    $NewPath = ($PathEntries + $InstallDir) -join ";"
    [System.Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Success "Added $InstallDir to your user PATH."
    Write-Warn "Note: New terminals will pick up the updated PATH automatically."
}

# ── Update PATH for current session ──────────────────────────────────────────
$env:Path = "$env:Path;$InstallDir"

# ── Verify ────────────────────────────────────────────────────────────────────
Write-Host ""
$Found = Get-Command "$BinaryName.exe" -ErrorAction SilentlyContinue
if ($Found) {
    Write-Success "✓ '$BinaryName' is ready to use!"
} else {
    Write-Warn "'$BinaryName' not found in current session PATH."
    Write-Host "  Restart your terminal, then try:" -ForegroundColor DarkGray
    Write-Host "  > $BinaryName --help" -ForegroundColor White
}

Write-Host ""
Write-Host "  Run: $BinaryName --help" -ForegroundColor Cyan
Write-Host ""
