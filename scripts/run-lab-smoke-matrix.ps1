param(
  [string]$Cases = "scripts\agent-lab-smoke-cases.json",
  [string[]]$CaseId = @(),
  [int]$HttpReadyTimeoutSeconds = 90,
  [int]$AgentTimeoutSeconds = 180,
  [switch]$SmokeActiveProof,
  [switch]$AllowPull,
  [switch]$RemoveImages,
  [switch]$ContinueOnFailure
)

$ErrorActionPreference = "Stop"

function Resolve-RepoPath([string]$Path) {
  if ([System.IO.Path]::IsPathRooted($Path)) {
    return (Resolve-Path -LiteralPath $Path).Path
  }
  return (Resolve-Path -LiteralPath (Join-Path (Get-Location) $Path)).Path
}

function Read-SmokeCases([string]$Path) {
  $resolved = Resolve-RepoPath $Path
  return (Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json).cases
}

function Read-BatchSummary([string]$RunDir) {
  $summaryPath = Join-Path $RunDir "summary.jsonl"
  if (-not (Test-Path -LiteralPath $summaryPath)) {
    return @()
  }
  $records = @()
  foreach ($line in Get-Content -LiteralPath $summaryPath) {
    if (-not $line.Trim()) { continue }
    $records += ($line | ConvertFrom-Json)
  }
  return $records
}

function Summarize-SmokeReport($Record) {
  if (-not $Record.smokeReport -or -not (Test-Path -LiteralPath $Record.smokeReport)) {
    return $null
  }
  $report = Get-Content -Raw -LiteralPath $Record.smokeReport | ConvertFrom-Json
  return [ordered]@{
    passed = [bool]$report.passed
    proof = $report.proof.status
    proofLevel = $report.proof.level
    capability = $report.proof.capability
    serviceCompromised = [bool]$report.serviceCompromised
    validatedFindings = @($report.storageSummary.findings | Where-Object state -eq "validated").Count
    firstQueueAfter = $report.queue.after[0].title
    failedAssertions = @($report.assertions | Where-Object { -not $_.passed } | ForEach-Object name)
  }
}

$repoRoot = (Resolve-Path -LiteralPath ".").Path
$allCases = @(Read-SmokeCases $Cases)
if ($CaseId.Count -gt 0) {
  $wanted = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($id in $CaseId) {
    foreach ($part in ([string]$id -split ",")) {
      $trimmed = $part.Trim()
      if ($trimmed) { [void]$wanted.Add($trimmed) }
    }
  }
  $allCases = @($allCases | Where-Object { $wanted.Contains([string]$_.id) })
}

$runId = "$(Get-Date -Format 'yyyyMMdd-HHmmss-fff')-$PID"
$matrixDir = Join-Path $repoRoot "data\lab-smoke-matrix\$runId"
New-Item -ItemType Directory -Force -Path $matrixDir | Out-Null
$matrixSummary = Join-Path $matrixDir "summary.json"
$batchScript = Join-Path $repoRoot "scripts\test-vulhub-batch.ps1"

$results = @()
$failed = $false
Write-Host "Lab smoke matrix cases: $($allCases.Count)"
Write-Host "Matrix directory: $matrixDir"

foreach ($case in $allCases) {
  $caseId = [string]$case.id
  $labRoot = [string]$case.labRoot
  if (-not $labRoot) {
    $results += [ordered]@{
      caseId = $caseId
      status = "skipped"
      reason = "case has no labRoot"
    }
    $failed = $true
    continue
  }

  $resolvedRoot = Join-Path $repoRoot $labRoot
  if (-not (Test-Path -LiteralPath $resolvedRoot)) {
    $results += [ordered]@{
      caseId = $caseId
      status = "skipped"
      reason = "labRoot not found: $labRoot"
    }
    $failed = $true
    continue
  }

  Write-Host "[$caseId] start"
  $before = @(Get-ChildItem -Path (Join-Path $repoRoot "data\vulhub-test-runs") -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
  $args = @(
    "-ExecutionPolicy", "Bypass",
    "-File", $batchScript,
    "-Root", $labRoot,
    "-BatchSize", "1",
    "-MaxTargets", "1",
    "-UseSmokeHarness",
    "-PreferDockerRun",
    "-HttpReadyTimeoutSeconds", "$HttpReadyTimeoutSeconds",
    "-AgentTimeoutSeconds", "$AgentTimeoutSeconds"
  )
  if (-not $AllowPull) {
    $args += "-RequireLocalImages"
  }
  if ($SmokeActiveProof) {
    $args += "-SmokeActiveProof"
  }
  if ($RemoveImages) {
    $args += "-RemoveImages"
  }
  & powershell @args
  $exitCode = $LASTEXITCODE
  $after = @(Get-ChildItem -Path (Join-Path $repoRoot "data\vulhub-test-runs") -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
  $newRun = $after | Where-Object { $before -notcontains $_.FullName } | Select-Object -First 1
  if (-not $newRun) {
    $newRun = $after | Select-Object -First 1
  }
  $records = if ($newRun) { @(Read-BatchSummary $newRun.FullName) } else { @() }
  $record = $records | Select-Object -Last 1
  $smoke = if ($record) { Summarize-SmokeReport $record } else { $null }
  $casePassed = $exitCode -eq 0 -and $record -and $record.status -eq "agent_smoke_passed" -and (!$smoke -or $smoke.passed)
  if (-not $casePassed) { $failed = $true }

  $results += [ordered]@{
    caseId = $caseId
    status = if ($record) { $record.status } else { "missing_summary" }
    passed = [bool]$casePassed
    exitCode = $exitCode
    target = if ($record) { $record.httpTarget } else { $null }
    batchRunDir = if ($newRun) { $newRun.FullName } else { $null }
    smokeReport = if ($record) { $record.smokeReport } else { $null }
    smokeDb = if ($record) { $record.smokeDb } else { $null }
    smoke = $smoke
  }

  if (-not $casePassed -and -not $ContinueOnFailure) {
    break
  }
}

$summary = [ordered]@{
  runId = $runId
  createdAt = (Get-Date).ToString("o")
  total = $results.Count
  passed = @($results | Where-Object passed).Count
  failed = @($results | Where-Object { -not $_.passed }).Count
  results = $results
}
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $matrixSummary -Encoding UTF8
Write-Host "Matrix summary: $matrixSummary"
Write-Host "Passed: $($summary.passed)/$($summary.total)"

if ($failed -and -not $ContinueOnFailure) {
  exit 1
}
