# ipregion launcher for Windows (PowerShell 5.1+ / PowerShell 7+).
# Locates a bash environment (Git Bash, MSYS2, Cygwin or WSL), fetches the
# script from the latest release when needed, and runs it with all
# arguments passed through.
#
# Works from PowerShell and from cmd.exe (via ipregion.cmd, which calls
# this file with -ExecutionPolicy Bypass).
$ErrorActionPreference = 'Stop'

# No param() block on purpose: everything (including dash-flags) must pass
# through to the bash script via $args. -Update is extracted manually.
$update = $false
$scriptArgs = @()
foreach ($a in $args) {
    if ($a -ieq '-update') {
        $update = $true
    }
    else {
        $scriptArgs += $a
    }
}
$scriptName = 'ipregion.sh'
$releaseUrl = 'https://github.com/vladon/ipregion/releases/latest/download/ipregion.sh'

# --- locate the script -----------------------------------------------------
$cacheDir = Join-Path $env:LOCALAPPDATA 'ipregion'
$cachedScript = Join-Path $cacheDir $scriptName
$localCandidates = @()
if (Get-Variable -Name PSScriptRoot -ErrorAction SilentlyContinue) {
    $localCandidates += (Join-Path $PSScriptRoot $scriptName)
}
$localCandidates += (Join-Path (Get-Location).Path $scriptName)

$script = $cachedScript
if (-not $update) {
    foreach ($candidate in $localCandidates) {
        if (Test-Path $candidate) {
            $script = $candidate
            break
        }
    }
}

if (-not (Test-Path $script) -or $update) {
    New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
    Write-Host "Downloading ipregion from $releaseUrl"
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        & curl.exe -fsSL $releaseUrl -o $cachedScript
        if ($LASTEXITCODE -ne 0) {
            throw "curl.exe failed with exit code $LASTEXITCODE"
        }
    }
    else {
        # curl.exe ships with Windows 10 1803+; this is the fallback
        Invoke-WebRequest -Uri $releaseUrl -OutFile $cachedScript -UseBasicParsing
    }
    $script = $cachedScript
}

# --- locate a bash environment ---------------------------------------------
$gitBashCandidates = @(
    "${env:ProgramFiles}\Git\bin\bash.exe",
    "${env:ProgramW6432}\Git\bin\bash.exe",
    "${env:ProgramFiles(x86)}\Git\bin\bash.exe",
    'C:\msys64\usr\bin\bash.exe',
    'C:\cygwin64\bin\bash.exe',
    'C:\cygwin\bin\bash.exe'
) | Where-Object { $_ -and (Test-Path $_) }

if ($gitBashCandidates.Count -gt 0) {
    $bash = $gitBashCandidates[0]
    & $bash $script @args
    exit $LASTEXITCODE
}

# --- WSL fallback -----------------------------------------------------------
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if ($wsl) {
    $wslScript = (& wsl.exe -e wslpath $script 2>$null | Select-Object -First 1)
    if ($wslScript) {
        $wslScript = $wslScript.Trim()
        & wsl.exe -e bash $wslScript @args
        exit $LASTEXITCODE
    }
    throw "wsl.exe is present, but wslpath failed. Install a distribution: wsl --install"
}

throw @'
No bash environment found. Install one of:
  - Git for Windows: https://git-scm.com/download/win (includes bash and curl)
  - WSL: wsl --install
  - MSYS2: https://www.msys2.org
'@
