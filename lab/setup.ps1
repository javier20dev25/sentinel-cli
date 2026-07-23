# Sentinel Red Team Lab Setup Script
# Installs Atomic Red Team and dependencies for local testing

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Sentinel Red Team Lab Setup" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

# ── 1. Prerequisites ──────────────────────────────────────────
Write-Host "`n[1/4] Checking prerequisites..." -ForegroundColor Yellow

$hasDotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $hasDotnet) {
    Write-Host "  Installing .NET SDK..." -ForegroundColor Gray
    winget install Microsoft.DotNet.SDK.8
}

$hasGit = Get-Command git -ErrorAction SilentlyContinue
if (-not $hasGit) {
    Write-Host "  Installing Git..." -ForegroundColor Gray
    winget install Git.Git
}

# ── 2. Clone Atomic Red Team ──────────────────────────────────
Write-Host "`n[2/4] Cloning Atomic Red Team..." -ForegroundColor Yellow

$atomicPath = "C:\AtomicRedTeam"
if (Test-Path -LiteralPath "$atomicPath\atomic-red-team\atomics") {
    Write-Host "  Already cloned at $atomicPath" -ForegroundColor Gray
} else {
    Write-Host "  Cloning to $atomicPath..." -ForegroundColor Gray
    git clone https://github.com/redcanaryco/atomic-red-team.git $atomicPath\atomic-red-team
}

# ── 3. Install Atomic Test Dependencies ───────────────────────
Write-Host "`n[3/4] Installing test dependencies..." -ForegroundColor Yellow

$atomicTestsPath = "$atomicPath\atomic-red-team\atomics"

# Create temp directories needed by tests
$tempDirs = @(
    "$env:TEMP\AtomicRedTeam",
    "$env:TEMP\AtomicTestParams"
)
foreach ($dir in $tempDirs) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  Created $dir" -ForegroundColor Gray
    }
}

# Create test directories
$testDirs = @(
    "$env:TEMP\AtomicRedTeam\T1055",
    "$env:TEMP\AtomicRedTeam\T1059",
    "$env:TEMP\AtomicRedTeam\T1218"
)
foreach ($dir in $testDirs) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

Write-Host "  Dependencies installed" -ForegroundColor Green

# ── 4. Verify Installation ────────────────────────────────────
Write-Host "`n[4/4] Verifying installation..." -ForegroundColor Yellow

$testCount = (Get-ChildItem -Path $atomicTestsPath -Recurse -Filter "*.yaml" -ErrorAction SilentlyContinue).Count
Write-Host "  Atomic tests available: $testCount" -ForegroundColor Gray

# Verify Sentinel CLI
$sentinelVersion = & node dist/cli/main.js --version 2>&1
Write-Host "  Sentinel CLI: $sentinelVersion" -ForegroundColor Gray

# ── Summary ────────────────────────────────────────────────────
Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "`n  Next steps:" -ForegroundColor White
Write-Host "    1. Review available tests:" -ForegroundColor Gray
Write-Host "       sentinel atomic --list" -ForegroundColor White
Write-Host "`n    2. Dry run (preview only):" -ForegroundColor Gray
Write-Host "       sentinel atomic --priority P1 --dry-run" -ForegroundColor White
Write-Host "`n    3. Generate PowerShell script:" -ForegroundColor Gray
Write-Host "       sentinel atomic --priority P1 --script > run-tests.ps1" -ForegroundColor White
Write-Host "`n    4. Execute tests (requires admin):" -ForegroundColor Gray
Write-Host "       sentinel atomic --priority P1 --run" -ForegroundColor White
Write-Host "`n  ⚠️  WARNING: Run tests in isolated VM only!" -ForegroundColor Red
Write-Host "     Do NOT run on production systems." -ForegroundColor Red
Write-Host ""