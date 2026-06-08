[CmdletBinding()]
param(
  [int]$Port = 3000,
  [string]$ListenHost = "127.0.0.1",
  [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Assert-Command([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $Name"
  }
}

Assert-Command "node"
Assert-Command "pnpm"

$envPath = Join-Path $repoRoot ".env"
if (Test-Path $envPath) {
  Get-Content -LiteralPath $envPath | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) {
      return
    }
    $name, $value = $line.Split("=", 2)
    if ($name) {
      $envName = $name.Trim()
      $envValue = $value.Trim()
      if ($envName -eq "AEGISPROBE_CONFIG" -and -not [System.IO.Path]::IsPathRooted($envValue)) {
        $envValue = Join-Path $repoRoot $envValue
      }
      [Environment]::SetEnvironmentVariable($envName, $envValue, "Process")
    }
  }
}

if (-not (Test-Path (Join-Path $repoRoot "node_modules"))) {
  Write-Host "[aegisprobe] Installing dependencies..." -ForegroundColor Cyan
  pnpm install
  if ($LASTEXITCODE -ne 0) {
    throw "pnpm install failed"
  }
}

Write-Host "[aegisprobe] Starting Web UI at http://$ListenHost`:$Port" -ForegroundColor Green
Write-Host "[aegisprobe] Press Ctrl+C to stop." -ForegroundColor DarkGray

$args = @("--filter", "@aegisprobe/cli", "dev", "webui", "--host", $ListenHost, "--port", "$Port")
if ($NoBrowser) {
  $args += "--no-browser"
}

& pnpm @args
exit $LASTEXITCODE
