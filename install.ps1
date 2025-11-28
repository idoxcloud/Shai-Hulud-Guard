# Shai-Hulud Guard One-Shot Installer & Runner for Windows
# Usage: irm https://raw.githubusercontent.com/idoxcloud/Shai-Hulud-Guard/main/install.ps1 | iex

param(
    [string]$Action = "report",
    [string]$Version = "v0.1-alpha.3",
    [string]$InstallDir = "$env:ProgramFiles\Shai-Hulud-Guard"
)

$ErrorActionPreference = "Stop"
$REPO = "idoxcloud/Shai-Hulud-Guard"

# Colors for output
function Write-Info {
    param([string]$Message)
    Write-Host "ℹ " -ForegroundColor Blue -NoNewline
    Write-Host $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "✗ " -ForegroundColor Red -NoNewline
    Write-Host $Message -ForegroundColor Red
}

# Detect architecture
function Get-Architecture {
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default {
            Write-ErrorMsg "Unsupported architecture: $arch"
            exit 1
        }
    }
}

# Check if running as administrator
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main installation logic
function Main {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════╗"
    Write-Host "║   Shai-Hulud Guard Installer & Runner      ║"
    Write-Host "╚════════════════════════════════════════════╝"
    Write-Host ""
    
    # Detect architecture
    Write-Info "Detecting platform..."
    $arch = Get-Architecture
    Write-Success "Detected architecture: windows-$arch"
    
    # Construct binary name and download URL
    $binaryName = "shai-hulud-guard-windows-$arch.exe"
    $downloadUrl = "https://github.com/$REPO/releases/download/$Version/$binaryName"
    
    # Create temporary directory
    $tmpDir = Join-Path $env:TEMP "shai-hulud-$(Get-Random)"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    
    try {
        $tmpBinary = Join-Path $tmpDir "shai-hulud-guard.exe"
        
        # Download binary
        Write-Info "Downloading $binaryName ($Version)..."
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpBinary -UseBasicParsing
            Write-Success "Downloaded successfully"
        } catch {
            Write-ErrorMsg "Failed to download binary from $downloadUrl"
            Write-Host $_.Exception.Message -ForegroundColor Red
            exit 1
        }
        
        # Perform action
        switch ($Action.ToLower()) {
            "install" {
                Write-Info "Installing to $InstallDir..."
                if (-not (Test-Administrator)) {
                    Write-ErrorMsg "Installation requires administrator privileges"
                    Write-Host ""
                    Write-Host "Please run PowerShell as Administrator and try again:"
                    Write-Host "  irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex" -ForegroundColor Cyan
                    Write-Host ""
                    Write-Host "Or use the inline syntax:"
                    Write-Host '  powershell -Command "irm https://raw.githubusercontent.com/' + $REPO + '/main/install.ps1 | iex"' -ForegroundColor Cyan
                    exit 1
                }
                
                # Create install directory
                if (-not (Test-Path $InstallDir)) {
                    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
                }
                
                # Copy binary
                $targetPath = Join-Path $InstallDir "shai-hulud-guard.exe"
                Copy-Item $tmpBinary $targetPath -Force
                
                # Add to PATH if not already there
                $currentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
                if ($currentPath -notlike "*$InstallDir*") {
                    Write-Info "Adding to system PATH..."
                    [Environment]::SetEnvironmentVariable(
                        "Path",
                        "$currentPath;$InstallDir",
                        [EnvironmentVariableTarget]::Machine
                    )
                    Write-Success "Added to PATH (restart shell to use)"
                }
                
                Write-Success "Installed to $targetPath"
                Write-Host ""
                Write-Info "To install protection, run (as Administrator):"
                Write-Host "  shai-hulud-guard -install" -ForegroundColor Cyan
                Write-Host ""
                Write-Info "To scan for threats, run:"
                Write-Host "  shai-hulud-guard -report" -ForegroundColor Cyan
            }
            
            {$_ -in "report", "scan"} {
                Write-Info "Running security report..."
                Write-Host ""
                & $tmpBinary -report
                Write-Host ""
                Write-Success "Report complete"
                Write-Host ""
                Write-Warning "To install permanently, run PowerShell as Administrator:"
                Write-Host '  irm https://raw.githubusercontent.com/' + $REPO + '/main/install.ps1 | iex' -ForegroundColor Cyan
            }
            
            "guard-install" {
                Write-Info "Installing Shai-Hulud Guard protection..."
                if (-not (Test-Administrator)) {
                    Write-ErrorMsg "Guard installation requires administrator privileges"
                    Write-Host ""
                    Write-Host "Please run PowerShell as Administrator and try again:"
                    Write-Host '  & ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/' + $REPO + '/main/install.ps1))) -Action guard-install' -ForegroundColor Cyan
                    exit 1
                }
                Write-Host ""
                & $tmpBinary -install -yes
            }
            
            "guard-uninstall" {
                Write-Info "Uninstalling Shai-Hulud Guard protection..."
                if (-not (Test-Administrator)) {
                    Write-ErrorMsg "Guard uninstallation requires administrator privileges"
                    Write-Host ""
                    Write-Host "Please run PowerShell as Administrator and try again:"
                    Write-Host '  & ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/' + $REPO + '/main/install.ps1))) -Action guard-uninstall' -ForegroundColor Cyan
                    exit 1
                }
                Write-Host ""
                & $tmpBinary -uninstall -yes
            }
            
            "status" {
                Write-Info "Checking protection status..."
                Write-Host ""
                & $tmpBinary -status
            }
            
            default {
                Write-ErrorMsg "Unknown action: $Action"
                Write-Host ""
                Write-Host "Usage:"
                Write-Host "  # Run report (default)"
                Write-Host "  irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Run scan"
                Write-Host '  & ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/' + $REPO + '/main/install.ps1))) -Action scan' -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Check status"
                Write-Host '  & ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/' + $REPO + '/main/install.ps1))) -Action status' -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Install binary (run as Administrator)"
                Write-Host '  & ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/' + $REPO + '/main/install.ps1))) -Action install' -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Install guard protection (run as Administrator)"
                Write-Host '  & ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/' + $REPO + '/main/install.ps1))) -Action guard-install' -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  # Uninstall guard protection (run as Administrator)"
                Write-Host '  & ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/' + $REPO + '/main/install.ps1))) -Action guard-uninstall' -ForegroundColor Cyan
                exit 1
            }
        }
    } finally {
        # Cleanup
        if (Test-Path $tmpDir) {
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Run main function
Main
