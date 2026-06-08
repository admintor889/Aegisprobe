$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$BinDir = Join-Path $ProjectRoot "tools\bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$GoExe = (Get-Command go -ErrorAction Stop).Source
$DefaultGoRoot = Split-Path (Split-Path $GoExe -Parent) -Parent
if (-not (Test-Path (Join-Path $env:GOROOT "src\context"))) {
  $env:GOROOT = $DefaultGoRoot
}
$env:GOBIN = $BinDir
if (-not $env:GOSUMDB) {
  $env:GOSUMDB = "sum.golang.org"
}

$Tools = @(
  "github.com/projectdiscovery/httpx/cmd/httpx@latest",
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
  "github.com/projectdiscovery/katana/cmd/katana@latest",
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
  "github.com/owasp-amass/amass/v5/cmd/amass@latest"
)

foreach ($Tool in $Tools) {
  Write-Host "Installing $Tool"
  & go install -v $Tool
}

function Test-ExecutableStarts {
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path $Path)) {
    return $false
  }
  try {
    $Process = Start-Process -FilePath $Path -ArgumentList "-version" -PassThru -Wait -WindowStyle Hidden
    return $Process.ExitCode -eq 0
  } catch {
    return $false
  }
}

function Install-NucleiRelease {
  $Version = "3.8.0"
  $TmpDir = Join-Path $ProjectRoot "tools\tmp\nuclei"
  $ZipPath = Join-Path $ProjectRoot "tools\tmp\nuclei_windows_amd64.zip"
  $Url = "https://github.com/projectdiscovery/nuclei/releases/download/v$Version/nuclei_$($Version)_windows_amd64.zip"
  New-Item -ItemType Directory -Force -Path (Split-Path $ZipPath -Parent) | Out-Null
  if (Test-Path $TmpDir) {
    Remove-Item -Recurse -Force $TmpDir
  }
  Write-Host "Installing nuclei release fallback $Url"
  Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing
  Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force
  $Nuclei = Get-ChildItem $TmpDir -Recurse -Filter "nuclei.exe" | Select-Object -First 1
  if (-not $Nuclei) {
    throw "nuclei.exe not found in release archive."
  }
  Copy-Item -LiteralPath $Nuclei.FullName -Destination (Join-Path $BinDir "nuclei.exe") -Force
}

$NucleiPath = Join-Path $BinDir "nuclei.exe"
if (-not (Test-ExecutableStarts -Path $NucleiPath)) {
  Install-NucleiRelease
}

Write-Host "`nInstalled binaries:"
Get-ChildItem $BinDir -Filter "*.exe" | Sort-Object Name | Select-Object Name, Length, LastWriteTime
