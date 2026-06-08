param(
  [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$TemplatesRoot = Join-Path $ProjectRoot "tools\templates"
$NucleiTemplates = Join-Path $TemplatesRoot "nuclei-templates"
$YakitRoot = Join-Path $ProjectRoot "third_party\security-tools\yakit"
$YaklangRoot = Join-Path $ProjectRoot "third_party\security-tools\yaklang"
$WappalyzerRoot = Join-Path $ProjectRoot "third_party\security-tools\wappalyzer"

New-Item -ItemType Directory -Force $TemplatesRoot | Out-Null
New-Item -ItemType Directory -Force (Split-Path $YakitRoot -Parent) | Out-Null

function Sync-GitRepo {
  param(
    [string]$Url,
    [string]$Path
  )

  if (Test-Path (Join-Path $Path ".git")) {
    git -C $Path pull --ff-only
  } else {
    git clone --depth 1 $Url $Path
  }
}

Sync-GitRepo "https://github.com/projectdiscovery/nuclei-templates" $NucleiTemplates
Sync-GitRepo "https://github.com/yaklang/yakit" $YakitRoot
Sync-GitRepo "https://github.com/yaklang/yaklang" $YaklangRoot
Sync-GitRepo "https://github.com/wapiti-scanner/wappalyzer" $WappalyzerRoot

if (-not $SkipBuild) {
  pnpm build
}

node (Join-Path $ProjectRoot "apps\cli\dist\index.js") knowledge sync
