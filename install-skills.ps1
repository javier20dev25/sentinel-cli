param(
    [switch]$All
)

$ErrorActionPreference = "Stop"
$SkillsDir = if ($env:SENTINEL_DIR) { Join-Path $env:SENTINEL_DIR "skills" } else { Join-Path $PSScriptRoot "skills" }

if (-not (Test-Path $SkillsDir)) {
    Write-Error "Skills directory not found at $SkillsDir. Set SENTINEL_DIR or run from project root."
    exit 1
}

function Install-ToDir {
    param([string]$TargetDir, [string]$AgentName)
    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
    $count = 0
    Get-ChildItem -Path $SkillsDir -Recurse -File | ForEach-Object {
        $dst = Join-Path $TargetDir $_.Name
        if (-not (Test-Path $dst) -or ((Get-Item $dst).LastWriteTime -lt $_.LastWriteTime)) {
            Copy-Item -Path $_.FullName -Destination $dst -Force
            $count++
        }
    }
    Write-Host "  [OK] $AgentName`: $count file(s) -> $TargetDir"
}

$installed = 0

# Claude
if (Get-Command claude -ErrorAction SilentlyContinue) {
    Install-ToDir -TargetDir (Join-Path $env:USERPROFILE ".claude\commands") -AgentName "claude"
    $installed++
}

# Cursor
if ((Get-Command cursor -ErrorAction SilentlyContinue) -or (Test-Path "$env:USERPROFILE\.cursor")) {
    Install-ToDir -TargetDir (Join-Path $env:USERPROFILE ".cursor\rules") -AgentName "cursor"
    $installed++
}

# Cline
$clineExt = "$env:USERPROFILE\.vscode\extensions\saoudrizwan.claude-dev"
if (Test-Path $clineExt) {
    Install-ToDir -TargetDir (Join-Path $clineExt "skills") -AgentName "cline"
    $installed++
}

# Windsurf
if ((Get-Command windsurf -ErrorAction SilentlyContinue) -or (Test-Path "$env:USERPROFILE\.windsurf")) {
    $wsFile = Join-Path $SkillsDir "adapters\windsurf\.windsurfrules"
    if (Test-Path $wsFile) {
        Copy-Item -Path $wsFile -Destination "$env:USERPROFILE\.windsurfrules" -Force
        Write-Host "  [OK] windsurf: .windsurfrules -> $env:USERPROFILE"
    }
    $installed++
}

# OpenCode
if ((Get-Command opencode -ErrorAction SilentlyContinue) -or (Test-Path "$env:USERPROFILE\.config\opencode")) {
    Install-ToDir -TargetDir "$env:USERPROFILE\.config\opencode\skills" -AgentName "opencode"
    $installed++
}

# Roo
if ((Get-Command roo -ErrorAction SilentlyContinue) -or (Test-Path "$env:USERPROFILE\.config\roo")) {
    Install-ToDir -TargetDir "$env:USERPROFILE\.config\roo\skills" -AgentName "roo"
    $installed++
}

# Gemini
if (Get-Command gemini -ErrorAction SilentlyContinue) {
    Install-ToDir -TargetDir "$env:USERPROFILE\.config\gemini\cli\skills" -AgentName "gemini"
    $installed++
}

# Codex
if (Get-Command codex -ErrorAction SilentlyContinue) {
    Install-ToDir -TargetDir "$env:USERPROFILE\.codex\skills" -AgentName "codex"
    $installed++
}

if ($installed -eq 0) {
    Write-Warning "No supported AI coding agents detected. Use -All to force install."
    exit 1
}

Write-Host "`nDone. Skills installed for $installed agent(s)."
