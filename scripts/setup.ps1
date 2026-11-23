# ==============================================================================
# PhishGuard AI - Automated Windows Environment Setup Script
# ==============================================================================
# This script inspects, installs, and configures all prerequisites and dependencies
# for the PhishGuard AI repository on Windows.
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$SkipInstallers,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

function Write-Step($title) {
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "[OK] $msg" -ForegroundColor Green
}

function Write-WarnMessage($msg) {
    Write-Host "[WARN] $msg" -ForegroundColor Yellow
}

function Write-ErrorMessage($msg) {
    Write-Host "[ERROR] $msg" -ForegroundColor Red
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Step "1. Validating Windows Environment Variables"

# Ensure COMSPEC is properly set to cmd.exe to avoid npm/node spawn issues
if ($env:COMSPEC -notlike "*cmd.exe") {
    Write-WarnMessage "COMSPEC was misconfigured ($env:COMSPEC). Resetting to cmd.exe..."
    $env:COMSPEC = "C:\WINDOWS\system32\cmd.exe"
    [Environment]::SetEnvironmentVariable("COMSPEC", "C:\WINDOWS\system32\cmd.exe", "User")
}
Write-Success "COMSPEC verified: $env:COMSPEC"

Write-Step "2. Checking Global Tool Prerequisites"

# 1. Git
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    $gitVer = & git --version
    Write-Success "Git detected: $gitVer"
} else {
    Write-WarnMessage "Git is missing."
    if (-not $SkipInstallers) {
        Write-Host "Installing Git using winget..." -ForegroundColor Yellow
        winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements
    }
}

# 2. Python (3.11+)
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
$pythonValid = $false
if ($pythonCmd) {
    $pyVerOutput = & python --version 2>&1
    Write-Host "Found Python: $pyVerOutput" -ForegroundColor DarkGray
    if ($pyVerOutput -match "Python (\d+)\.(\d+)") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -ge 3 -and $minor -ge 11) {
            $pythonValid = $true
            Write-Success "Python version is compatible: $pyVerOutput"
        }
    }
}

if (-not $pythonValid) {
    Write-WarnMessage "Compatible Python (>= 3.11) not found."
    if (-not $SkipInstallers) {
        Write-Host "Installing Python 3.12 using winget..." -ForegroundColor Yellow
        winget install --id Python.Python.3.12 -e --accept-source-agreements --accept-package-agreements
    }
}

# 3. Node.js & npm
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
$npmCmd = Get-Command npm -ErrorAction SilentlyContinue

if ($nodeCmd -and $npmCmd) {
    $nodeVer = & node --version
    $npmVer = & npm --version
    Write-Success "Node.js detected: $nodeVer"
    Write-Success "npm detected: $npmVer"
} else {
    Write-WarnMessage "Node.js or npm is missing."
    if (-not $SkipInstallers) {
        Write-Host "Installing Node.js LTS using winget..." -ForegroundColor Yellow
        winget install --id OpenJS.NodeJS.LTS -e --accept-source-agreements --accept-package-agreements
    }
}

# 4. MySQL Server (8.x)
$mysqlCmd = Get-Command mysql -ErrorAction SilentlyContinue
if ($mysqlCmd) {
    $mysqlVer = & mysql --version
    Write-Success "MySQL client detected: $mysqlVer"
} else {
    # Check standard install locations
    $knownMySqlBin = (Get-ChildItem -Path "C:\Program Files\MySQL" -Filter "mysql.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1)?.DirectoryName
    if ($knownMySqlBin -and (Test-Path "$knownMySqlBin\mysql.exe")) {
        Write-Success "Found MySQL binary at: $knownMySqlBin"
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentPath -notlike "*$knownMySqlBin*") {
            Write-Host "Adding $knownMySqlBin to User PATH..." -ForegroundColor Yellow
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$knownMySqlBin", "User")
            $env:Path = "$env:Path;$knownMySqlBin"
            Write-Success "Added MySQL to User PATH."
        }
    } else {
        Write-WarnMessage "MySQL Server (8.x) not found."
        if (-not $SkipInstallers) {
            Write-Host "Installing MySQL 8.4 LTS via winget..." -ForegroundColor Yellow
            winget install --id Oracle.MySQL -e --accept-source-agreements --accept-package-agreements
            
            # Re-check install location and add to PATH
            $knownMySqlBin = (Get-ChildItem -Path "C:\Program Files\MySQL" -Filter "mysql.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1)?.DirectoryName
            if ($knownMySqlBin) {
                $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
                [Environment]::SetEnvironmentVariable("Path", "$currentPath;$knownMySqlBin", "User")
                $env:Path = "$env:Path;$knownMySqlBin"
                Write-Success "MySQL 8.x installed and added to User PATH: $knownMySqlBin"
            }
        }
    }
}

Write-Step "3. Setting up Backend Environment (.venv & requirements)"
$backendDir = Join-Path $RepoRoot "backend"
Set-Location $backendDir

# Create .env from .env.example if missing
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Success "Created backend/.env from backend/.env.example"
    }
} else {
    Write-Success "backend/.env already exists."
}

# Create virtual environment if missing
$venvPython = Join-Path $backendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "Creating Python virtual environment in backend/.venv..." -ForegroundColor DarkGray
    & python -m venv .venv
    Write-Success "Virtual environment created."
} else {
    Write-Success "Virtual environment already exists."
}

# Install backend dependencies
Write-Host "Installing backend Python packages from requirements.txt..." -ForegroundColor DarkGray
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r requirements.txt --quiet
Write-Success "Backend Python dependencies installed."

# Run tests if requested
if (-not $SkipTests) {
    Write-Host "Running backend tests..." -ForegroundColor DarkGray
    & $venvPython -m pytest
    if ($LASTEXITCODE -eq 0) {
        Write-Success "All backend tests passed!"
    } else {
        Write-WarnMessage "Some backend tests had warnings or failures."
    }
}

Write-Step "4. Setting up Frontend Environment (Vite + React + Tailwind CSS)"
$frontendDir = Join-Path $RepoRoot "frontend"
Set-Location $frontendDir

Write-Host "Installing frontend npm packages..." -ForegroundColor DarkGray
& npm install --quiet
Write-Success "Frontend dependencies installed."

Write-Host "Verifying frontend build..." -ForegroundColor DarkGray
& npm run build
if ($LASTEXITCODE -eq 0) {
    Write-Success "Frontend built successfully with Vite and Tailwind CSS!"
} else {
    Write-WarnMessage "Frontend build encountered an issue."
}

Write-Step "Setup Complete! Summary & Next Steps"
Write-Host @"
--------------------------------------------------------------------------------
PhishGuard AI Environment is Ready!

Next Steps for Teammates:
1. Terminal Restart:
   - If MySQL or Node was just added to your PATH, restart your PowerShell
     window so the updated PATH takes effect globally.

2. MySQL Server Configuration:
   - Ensure your MySQL Windows service is running:
       Get-Service -Name *mysql*
   - Default root password: If newly installed with Oracle.MySQL MSI,
     configure your root password or run the MySQL Instance Config Wizard,
     and update backend/.env accordingly:
       MYSQL_PASSWORD=your_password

3. Run Backend (FastAPI):
   - cd backend
   - .\.venv\Scripts\Activate.ps1
   - uvicorn app.main:app --reload --port 8000
   - Docs available at: http://localhost:8000/docs

4. Run Frontend (React + Vite + Tailwind):
   - cd frontend
   - npm run dev
   - Web app available at: http://localhost:5173

--------------------------------------------------------------------------------
"@ -ForegroundColor Green

Set-Location $RepoRoot
