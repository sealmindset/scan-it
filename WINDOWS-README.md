# scan-it for Windows

Dockerized security scanner that combines **NeMo Guardrails AI safety testing** + **OWASP Testing Guide** + **dependency scanning** + **static analysis** into a single container. No Claude Code required.

## Prerequisites

1. **Docker Desktop for Windows** -- Download and install from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/)
   - During installation, enable **WSL 2 backend** (recommended) or Hyper-V
   - After install, open Docker Desktop and ensure it says "Docker is running"
2. **Git for Windows** -- Download from [git-scm.com](https://git-scm.com/download/win) (includes Git Bash)

## Quick Start

### PowerShell

```powershell
# Clone the repository
git clone https://github.com/sealmindset/scan-it.git
cd scan-it

# Build the Docker image (one-time setup)
docker build -t scan-it .

# Scan your project
docker run --rm -v C:\path\to\your\project:/app:ro -v C:\path\to\output:/output scan-it
```

### Command Prompt (cmd.exe)

```cmd
git clone https://github.com/sealmindset/scan-it.git
cd scan-it

docker build -t scan-it .

docker run --rm -v C:\path\to\your\project:/app:ro -v C:\path\to\output:/output scan-it
```

### Git Bash

```bash
git clone https://github.com/sealmindset/scan-it.git
cd scan-it

docker build -t scan-it .

docker run --rm -v /c/path/to/your/project:/app:ro -v /c/path/to/output:/output scan-it
```

> **Note:** In Git Bash, Windows paths use `/c/Users/...` instead of `C:\Users\...`

## Step-by-Step Example

This example scans a project located at `C:\Users\jsmith\repos\my-app`.

### PowerShell

```powershell
# 1. Build the scanner (only needed once)
cd C:\Users\jsmith\repos\scan-it
docker build -t scan-it .

# 2. Create an output folder for reports
mkdir C:\Users\jsmith\repos\my-app\scan-it-reports

# 3. Run a full scan
docker run --rm `
  -v C:\Users\jsmith\repos\my-app:/app:ro `
  -v C:\Users\jsmith\repos\my-app\scan-it-reports:/output `
  scan-it

# 4. Run SAST only
docker run --rm `
  -v C:\Users\jsmith\repos\my-app:/app:ro `
  -v C:\Users\jsmith\repos\my-app\scan-it-reports:/output `
  scan-it sast

# 5. Full scan with JSON output
docker run --rm `
  -v C:\Users\jsmith\repos\my-app:/app:ro `
  -v C:\Users\jsmith\repos\my-app\scan-it-reports:/output `
  scan-it full --format json
```

> **PowerShell tip:** Use backtick (`` ` ``) for line continuation, not backslash (`\`).

### Command Prompt (cmd.exe)

```cmd
:: 1. Build the scanner
cd C:\Users\jsmith\repos\scan-it
docker build -t scan-it .

:: 2. Create output folder
mkdir C:\Users\jsmith\repos\my-app\scan-it-reports

:: 3. Run a full scan
docker run --rm ^
  -v C:\Users\jsmith\repos\my-app:/app:ro ^
  -v C:\Users\jsmith\repos\my-app\scan-it-reports:/output ^
  scan-it

:: 4. SAST only
docker run --rm ^
  -v C:\Users\jsmith\repos\my-app:/app:ro ^
  -v C:\Users\jsmith\repos\my-app\scan-it-reports:/output ^
  scan-it sast
```

> **cmd.exe tip:** Use caret (`^`) for line continuation.

## Windows Convenience Script (scan-it.bat)

Save this as `scan-it.bat` in the `scan-it` directory for easier usage:

```bat
@echo off
setlocal

set TARGET=%~1
set MODE=%2
if "%TARGET%"=="" (
    echo Usage: scan-it.bat C:\path\to\project [mode] [--format json^|junit]
    echo.
    echo Modes: full, sast, deps, owasp, guardrails
    echo.
    echo Examples:
    echo   scan-it.bat C:\Users\jsmith\repos\my-app
    echo   scan-it.bat C:\Users\jsmith\repos\my-app sast
    echo   scan-it.bat C:\Users\jsmith\repos\my-app full --format json
    exit /b 1
)

if "%MODE%"=="" set MODE=full

:: Resolve to absolute path
pushd %TARGET% 2>nul
if errorlevel 1 (
    echo ERROR: Directory not found: %TARGET%
    exit /b 1
)
set TARGET=%CD%
popd

:: Create output directory
if not exist "%TARGET%\scan-it-reports" mkdir "%TARGET%\scan-it-reports"

:: Build image if not present
docker image inspect scan-it >nul 2>&1
if errorlevel 1 (
    echo Building scan-it Docker image...
    docker build -t scan-it "%~dp0"
    echo.
)

echo Scanning: %TARGET%
echo Mode: %MODE%
echo Output: %TARGET%\scan-it-reports
echo.

:: Shift past TARGET and MODE to pass remaining args
shift
shift
docker run --rm -v "%TARGET%":/app:ro -v "%TARGET%\scan-it-reports":/output scan-it %MODE% %1 %2 %3 %4

echo.
echo Reports saved to: %TARGET%\scan-it-reports\
```

Usage:

```cmd
scan-it.bat C:\Users\jsmith\repos\my-app
scan-it.bat C:\Users\jsmith\repos\my-app sast
scan-it.bat C:\Users\jsmith\repos\my-app full --format json
```

## PowerShell Convenience Script (scan-it.ps1)

Save this as `scan-it.ps1` in the `scan-it` directory:

```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [ValidateSet("full", "sast", "deps", "owasp", "guardrails")]
    [string]$Mode = "full",

    [ValidateSet("json", "junit", "")]
    [string]$Format = ""
)

$ErrorActionPreference = "Stop"

# Resolve target path
$Target = (Resolve-Path $Target).Path
if (-not (Test-Path $Target -PathType Container)) {
    Write-Error "Target directory not found: $Target"
    exit 1
}

# Create output directory
$OutputDir = Join-Path $Target "scan-it-reports"
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Build image if needed
$imageExists = docker image inspect scan-it 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Building scan-it Docker image..."
    docker build -t scan-it $PSScriptRoot
    Write-Host ""
}

Write-Host "Scanning: $Target"
Write-Host "Mode: $Mode"
Write-Host "Output: $OutputDir"
Write-Host ""

# Build docker command
$dockerArgs = @("run", "--rm", "-v", "${Target}:/app:ro", "-v", "${OutputDir}:/output", "scan-it", $Mode)
if ($Format) {
    $dockerArgs += "--format"
    $dockerArgs += $Format
}

docker @dockerArgs
$exitCode = $LASTEXITCODE

Write-Host ""
Write-Host "Reports saved to: $OutputDir\"

exit $exitCode
```

Usage:

```powershell
.\scan-it.ps1 -Target C:\Users\jsmith\repos\my-app
.\scan-it.ps1 -Target C:\Users\jsmith\repos\my-app -Mode sast
.\scan-it.ps1 -Target C:\Users\jsmith\repos\my-app -Mode full -Format json
```

> **Note:** You may need to run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once to allow PowerShell scripts.

## Scan Modes

| Mode | Command | What It Scans |
|------|---------|---------------|
| **Full** (default) | `scan-it full` | Everything below |
| **SAST** | `scan-it sast` | Semgrep, Bandit, ESLint security, pattern checks |
| **Deps** | `scan-it deps` | npm audit, pip-audit, Trivy |
| **OWASP** | `scan-it owasp` | OWASP Testing Guide config/code checks |
| **Guardrails** | `scan-it guardrails` | NeMo AI safety checks (if AI features detected) |

## Output Formats

Markdown attestation is always generated. Optionally add JSON or JUnit XML:

```powershell
# Markdown + JSON
docker run --rm -v C:\my\project:/app:ro -v C:\my\output:/output scan-it full --format json

# Markdown + JUnit XML (for CI/CD)
docker run --rm -v C:\my\project:/app:ro -v C:\my\output:/output scan-it full --format junit
```

Reports are saved to the output directory you specify (or `<project>\scan-it-reports\` if using the wrapper scripts).

## Docker Compose (Windows)

```powershell
cd C:\Users\jsmith\repos\my-app

# Set target and run
$env:SCAN_TARGET = "."
docker compose -f C:\Users\jsmith\repos\scan-it\docker-compose.yml run --rm scan-it
```

## Troubleshooting

### "Docker is not running"

Open Docker Desktop from the Start Menu and wait for it to show "Docker is running" in the bottom-left corner.

### "failed to read dockerfile: no such file or directory"

You ran `docker build` from the wrong directory. You must be inside the `scan-it` folder:

```powershell
cd C:\Users\jsmith\repos\scan-it    # <-- the scan-it directory, not your project
docker build -t scan-it .
```

### Volume mount errors / "invalid mount config"

Windows paths must use the full path. Docker Desktop must have access to the drive:

1. Open **Docker Desktop** > **Settings** > **Resources** > **File Sharing**
2. Ensure the drive (e.g., `C:\`) is shared
3. Use the full absolute path in volume mounts

```powershell
# Correct
-v C:\Users\jsmith\repos\my-app:/app:ro

# Wrong
-v .\my-app:/app:ro
-v my-app:/app:ro
```

### "Permission denied" on PowerShell scripts

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Slow first build

The first `docker build` downloads Python, Node.js, and all security tools. This is a one-time operation (~2-5 minutes depending on your connection). Subsequent builds use Docker cache and are much faster.

### WSL 2 path mapping

If you use WSL 2 with Docker, you can access Windows files from WSL at `/mnt/c/`:

```bash
# From WSL terminal
docker run --rm \
  -v /mnt/c/Users/jsmith/repos/my-app:/app:ro \
  -v /mnt/c/Users/jsmith/repos/my-app/scan-it-reports:/output \
  scan-it
```

## CI/CD Integration (Azure DevOps)

```yaml
trigger:
  - main

pool:
  vmImage: 'windows-latest'

steps:
  - task: DockerInstaller@0
    inputs:
      dockerVersion: '20.10'

  - script: |
      docker build -t scan-it $(Build.SourcesDirectory)\scan-it
      docker run --rm ^
        -v $(Build.SourcesDirectory):/app:ro ^
        -v $(Build.ArtifactStagingDirectory):/output ^
        scan-it full --format junit
    displayName: 'Run Security Scan'

  - task: PublishTestResults@2
    inputs:
      testResultsFormat: 'JUnit'
      testResultsFiles: '**/*-junit.xml'
      searchFolder: '$(Build.ArtifactStagingDirectory)'
    displayName: 'Publish Scan Results'
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings |
| 1 | High-severity findings detected |
| 2 | Critical-severity findings detected |

## Safety Guarantees

- **Non-destructive**: All scans are read-only analysis. Your code is mounted as read-only (`:ro`).
- **No network probing**: Static/config analysis only. No active DAST.
- **No data exfiltration**: All findings stay local in your output directory.
- **Deterministic**: Same input produces same output. No external API calls during scanning.

## License

CC0 1.0 Universal -- Public Domain
