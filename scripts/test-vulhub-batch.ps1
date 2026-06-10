param(
  [string]$Root = "labs\targets\vulhub",
  [int]$BatchSize = 3,
  [int]$StartIndex = 0,
  [int]$MaxTargets = 0,
  [int]$ComposeUpTimeoutSeconds = 180,
  [int]$HttpReadyTimeoutSeconds = 45,
  [int]$AgentTimeoutSeconds = 180,
  [string]$SmokeCases = "scripts\agent-lab-smoke-cases.json",
  [switch]$PreferDockerRun,
  [switch]$RemoveImages,
  [switch]$UseSmokeHarness,
  [switch]$SmokeActiveProof,
  [switch]$RequireLocalImages,
  [switch]$DisableSingleServiceDockerRun,
  [switch]$SkipAgent
)

$ErrorActionPreference = "Stop"

function Resolve-RepoPath([string]$Path) {
  if ([System.IO.Path]::IsPathRooted($Path)) {
    return (Resolve-Path -LiteralPath $Path).Path
  }
  return (Resolve-Path -LiteralPath (Join-Path (Get-Location) $Path)).Path
}

function Quote-NativeArg([string]$Arg) {
  if ($null -eq $Arg) { return '""' }
  if ($Arg -notmatch '[\s"]') { return $Arg }
  return '"' + ($Arg -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Run-LoggedCommand([string]$File, [string[]]$CommandArgs, [string]$WorkDir, [string]$LogFile, [int]$TimeoutSeconds = 0) {
  Add-Content -LiteralPath $LogFile -Value "COMMAND: $File $($CommandArgs -join ' ')"
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $File
  $psi.Arguments = ($CommandArgs | ForEach-Object { Quote-NativeArg $_ }) -join " "
  $psi.WorkingDirectory = $WorkDir
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $process = [System.Diagnostics.Process]::Start($psi)
  $stdoutTask = $process.StandardOutput.ReadToEndAsync()
  $stderrTask = $process.StandardError.ReadToEndAsync()
  if ($TimeoutSeconds -gt 0) {
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
      try { $process.Kill($true) } catch {}
      try { $process.WaitForExit(5000) | Out-Null } catch {}
      Add-Content -LiteralPath $LogFile -Value "TIMEOUT after $TimeoutSeconds seconds: $File $($CommandArgs -join ' ')"
      try {
        $stdoutTask.Wait(5000) | Out-Null
        $stderrTask.Wait(5000) | Out-Null
        Add-Content -LiteralPath $LogFile -Value ($stdoutTask.Result)
        Add-Content -LiteralPath $LogFile -Value ($stderrTask.Result)
      } catch {}
      return 124
    }
  } else {
    $process.WaitForExit()
  }
  $stdoutTask.Wait() | Out-Null
  $stderrTask.Wait() | Out-Null
  Add-Content -LiteralPath $LogFile -Value ($stdoutTask.Result)
  Add-Content -LiteralPath $LogFile -Value ($stderrTask.Result)
  return $process.ExitCode
}

function Test-LogHasDockerMissingContainerError([string]$LogFile) {
  if (-not (Test-Path -LiteralPath $LogFile)) { return $false }
  try {
    return [bool](Select-String -LiteralPath $LogFile -Pattern "Error response from daemon:.*No such container" -Quiet)
  } catch {
    return $false
  }
}

function Compose-Args([string]$ProjectName, [string[]]$SubcommandArgs) {
  $composeArgs = @("compose")
  if ($ProjectName) {
    $composeArgs += @("-p", $ProjectName)
  }
  $composeArgs += $SubcommandArgs
  return $composeArgs
}

function Short-Hash([string]$Value) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "").Substring(0, 10)
  } finally {
    $sha.Dispose()
  }
}

function Get-ComposePublishers([string]$ComposeDir, [string]$ProjectName) {
  Push-Location $ComposeDir
  $oldErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $composeArgs = Compose-Args $ProjectName @("ps", "--format", "json")
    $raw = & docker @composeArgs 2>$null
  } finally {
    $ErrorActionPreference = $oldErrorActionPreference
    Pop-Location
  }
  $items = @()
  foreach ($line in $raw) {
    if (-not $line.Trim()) { continue }
    $dockerRunState = $null
    try {
      $items += ($line | ConvertFrom-Json)
    } catch {}
  }
  $publishers = @()
  foreach ($item in $items) {
    foreach ($publisher in @($item.Publishers)) {
      if ($publisher.PublishedPort -and $publisher.Protocol -eq "tcp") {
        $publishers += [pscustomobject]@{
          Service = $item.Service
          Image = $item.Image
          Host = if ($publisher.URL) { $publisher.URL } else { "127.0.0.1" }
          Port = [int]$publisher.PublishedPort
          TargetPort = [int]$publisher.TargetPort
        }
      }
    }
  }
  return $publishers
}

function Get-ComposeConfig([string]$ComposeDir) {
  Push-Location $ComposeDir
  $oldErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "SilentlyContinue"
    $raw = (& docker compose config --format json 2>$null) -join "`n"
  } finally {
    $ErrorActionPreference = $oldErrorActionPreference
    Pop-Location
  }
  if (-not $raw.Trim()) { return $null }
  $start = $raw.IndexOf("{")
  $end = $raw.LastIndexOf("}")
  if ($start -lt 0 -or $end -lt $start) { return $null }
  return $raw.Substring($start, $end - $start + 1) | ConvertFrom-Json
}

function Get-SingleServiceFromComposeConfig($Config) {
  if (-not $Config -or -not $Config.services) { return $null }
  $serviceNames = @($Config.services.PSObject.Properties.Name)
  if ($serviceNames.Count -ne 1) { return $null }
  $name = $serviceNames[0]
  return [pscustomobject]@{
    Name = $name
    Service = $Config.services.$name
  }
}

function Test-SingleServiceDockerRunCandidate([string]$ComposeDir) {
  $config = Get-ComposeConfig $ComposeDir
  $single = Get-SingleServiceFromComposeConfig $config
  if (-not $single -or -not $single.Service.image) { return $false }
  return @($single.Service.ports).Count -gt 0
}

function Get-ComposeImages($Config) {
  if (-not $Config -or -not $Config.services) { return @() }
  $images = @()
  foreach ($serviceName in @($Config.services.PSObject.Properties.Name)) {
    $image = [string]$Config.services.$serviceName.image
    if ($image) {
      $images += $image
    }
  }
  return @($images | Sort-Object -Unique)
}

function Get-MissingLocalImages([string]$ComposeDir) {
  $config = Get-ComposeConfig $ComposeDir
  $missing = @()
  foreach ($image in Get-ComposeImages $config) {
    $inspectExitCode = 1
    $oldErrorActionPreference = $ErrorActionPreference
    try {
      $ErrorActionPreference = "Continue"
      & docker image inspect $image *> $null
      $inspectExitCode = $LASTEXITCODE
    } catch {
      $inspectExitCode = 1
    } finally {
      $ErrorActionPreference = $oldErrorActionPreference
    }
    if ($inspectExitCode -ne 0) {
      $missing += $image
    }
  }
  return $missing
}

function Get-DockerContainerSnapshot() {
  $items = @{}
  $ok = $false
  $oldErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $raw = & docker ps -a --no-trunc --format "{{.ID}}`t{{.Names}}`t{{.Image}}" 2>$null
    $ok = $LASTEXITCODE -eq 0
  } catch {
    $ok = $false
    $raw = @()
  } finally {
    $ErrorActionPreference = $oldErrorActionPreference
  }
  if ($ok) {
    foreach ($line in @($raw)) {
      if (-not $line.Trim()) { continue }
      $parts = $line -split "`t", 3
      $id = $parts[0].Trim()
      if ($id) { $items[$id] = $line.Trim() }
    }
  }
  return [pscustomobject]@{ Ok = $ok; Items = $items }
}

function Get-DockerImageSnapshot() {
  $items = @{}
  $ok = $false
  $oldErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $raw = & docker images --no-trunc --format "{{.ID}}`t{{.Repository}}:{{.Tag}}" 2>$null
    $ok = $LASTEXITCODE -eq 0
  } catch {
    $ok = $false
    $raw = @()
  } finally {
    $ErrorActionPreference = $oldErrorActionPreference
  }
  if ($ok) {
    foreach ($line in @($raw)) {
      if (-not $line.Trim()) { continue }
      $parts = $line -split "`t", 2
      $id = $parts[0].Trim()
      if ($id) { $items[$id] = $line.Trim() }
    }
  }
  return [pscustomobject]@{ Ok = $ok; Items = $items }
}

function Remove-NewDockerContainers($BeforeSnapshot, [string]$WorkDir, [string]$LogFile) {
  if (-not $BeforeSnapshot -or -not $BeforeSnapshot.Ok) {
    Add-Content -LiteralPath $LogFile -Value "SNAPSHOT CLEANUP SKIPPED: initial container snapshot failed"
    return
  }
  $afterSnapshot = Get-DockerContainerSnapshot
  if (-not $afterSnapshot.Ok) {
    Add-Content -LiteralPath $LogFile -Value "SNAPSHOT CLEANUP SKIPPED: final container snapshot failed"
    return
  }
  foreach ($id in @($afterSnapshot.Items.Keys)) {
    if ($BeforeSnapshot.Items.ContainsKey($id)) { continue }
    Add-Content -LiteralPath $LogFile -Value "SNAPSHOT CLEANUP CONTAINER: $($afterSnapshot.Items[$id])"
    Run-LoggedCommand -File "docker" -CommandArgs @("rm", "-f", $id) -WorkDir $WorkDir -LogFile $LogFile -TimeoutSeconds 60 | Out-Null
  }
}

function Remove-NewDockerImages($BeforeSnapshot, [string]$WorkDir, [string]$LogFile) {
  if (-not $BeforeSnapshot -or -not $BeforeSnapshot.Ok) {
    Add-Content -LiteralPath $LogFile -Value "SNAPSHOT CLEANUP SKIPPED: initial image snapshot failed"
    return
  }
  $afterSnapshot = Get-DockerImageSnapshot
  if (-not $afterSnapshot.Ok) {
    Add-Content -LiteralPath $LogFile -Value "SNAPSHOT CLEANUP SKIPPED: final image snapshot failed"
    return
  }
  foreach ($id in @($afterSnapshot.Items.Keys)) {
    if ($BeforeSnapshot.Items.ContainsKey($id)) { continue }
    Add-Content -LiteralPath $LogFile -Value "SNAPSHOT CLEANUP IMAGE: $($afterSnapshot.Items[$id])"
    Run-LoggedCommand -File "docker" -CommandArgs @("rmi", "-f", $id) -WorkDir $WorkDir -LogFile $LogFile -TimeoutSeconds 180 | Out-Null
  }
}

function Get-ServiceEnvironmentArgs($Service) {
  $args = @()
  $environment = $Service.environment
  if (-not $environment) { return $args }
  if ($environment -is [array]) {
    foreach ($entry in @($environment)) {
      if ($entry) { $args += @("-e", [string]$entry) }
    }
    return $args
  }
  if ($environment.PSObject -and $environment.PSObject.Properties) {
    foreach ($property in @($environment.PSObject.Properties)) {
      if ($null -ne $property.Value) {
        $args += @("-e", "$($property.Name)=$($property.Value)")
      }
    }
  }
  return $args
}

function Get-ServiceCommandArgs($Value) {
  if (-not $Value) { return @() }
  if ($Value -is [array]) {
    return @($Value | ForEach-Object { [string]$_ })
  }
  return @([string]$Value)
}

function Test-TcpPortAvailable([string]$HostIp, [int]$Port) {
  $listener = $null
  try {
    $address = [System.Net.IPAddress]::Parse($HostIp)
    $listener = [System.Net.Sockets.TcpListener]::new($address, $Port)
    $listener.Start()
    return $true
  } catch {
    return $false
  } finally {
    if ($listener) { $listener.Stop() }
  }
}

function Get-AvailableTcpPort([string]$HostIp) {
  $listener = $null
  try {
    $address = [System.Net.IPAddress]::Parse($HostIp)
    $listener = [System.Net.Sockets.TcpListener]::new($address, 0)
    $listener.Start()
    return [int]$listener.LocalEndpoint.Port
  } finally {
    if ($listener) { $listener.Stop() }
  }
}

function Resolve-ServicePortMappings($Service) {
  $mappings = @()
  foreach ($port in @($Service.ports)) {
    if ($port.protocol -and $port.protocol -ne "tcp") { continue }
    $target = [string]$port.target
    if (-not $target) { continue }
    $hostIp = if ($port.host_ip) { [string]$port.host_ip } else { "127.0.0.1" }
    $originalPublished = if ($port.published) { [int]$port.published } else { 0 }
    $published = $originalPublished
    $remapped = $false
    if ($published -le 0 -or -not (Test-TcpPortAvailable $hostIp $published)) {
      $published = Get-AvailableTcpPort $hostIp
      $remapped = $true
    }
    $mappings += [pscustomobject]@{
      HostIp = $hostIp
      Published = [int]$published
      OriginalPublished = [int]$originalPublished
      Target = [int]$target
      Protocol = "tcp"
      Remapped = [bool]$remapped
    }
  }
  return $mappings
}

function New-DockerRunNetwork([string]$NetworkName, [string]$ComposeDir, [string]$LogFile) {
  $networkCode = Run-LoggedCommand -File "docker" -CommandArgs @("network", "create", $NetworkName) -WorkDir $ComposeDir -LogFile $LogFile -TimeoutSeconds 30
  if ($networkCode -eq 0) {
    return 0
  }
  for ($attempt = 0; $attempt -lt 32; $attempt += 1) {
    $octet = 10 + $attempt
    $subnet = "10.250.$octet.0/24"
    $networkCode = Run-LoggedCommand -File "docker" -CommandArgs @("network", "create", "--subnet", $subnet, $NetworkName) -WorkDir $ComposeDir -LogFile $LogFile -TimeoutSeconds 30
    if ($networkCode -eq 0) {
      return 0
    }
  }
  return $networkCode
}

function Get-ServiceDependsOnNames($Service) {
  $dependsOn = $Service.depends_on
  if (-not $dependsOn) { return @() }
  if ($dependsOn -is [array]) {
    return @($dependsOn | ForEach-Object { [string]$_ })
  }
  if ($dependsOn.PSObject -and $dependsOn.PSObject.Properties) {
    return @($dependsOn.PSObject.Properties.Name)
  }
  return @()
}

function Get-ComposeServiceStartOrder($Config) {
  $serviceNames = @($Config.services.PSObject.Properties.Name)
  $remaining = [System.Collections.Generic.List[string]]::new()
  foreach ($serviceName in $serviceNames) { $remaining.Add([string]$serviceName) }
  $started = New-Object System.Collections.Generic.HashSet[string]
  $ordered = @()
  while ($remaining.Count -gt 0) {
    $progress = $false
    foreach ($serviceName in @($remaining)) {
      $deps = @(Get-ServiceDependsOnNames $Config.services.$serviceName)
      $blocked = @($deps | Where-Object { $serviceNames -contains $_ -and -not $started.Contains($_) })
      if ($blocked.Count -eq 0) {
        $ordered += $serviceName
        $started.Add($serviceName) | Out-Null
        $remaining.Remove($serviceName) | Out-Null
        $progress = $true
      }
    }
    if (-not $progress) {
      foreach ($serviceName in @($remaining)) {
        $ordered += $serviceName
        $remaining.Remove($serviceName) | Out-Null
      }
    }
  }
  return $ordered
}

function Add-ServiceDockerRunArgs([string[]]$RunArgs, $Service, [string]$NetworkName, [string]$ServiceName, [object[]]$PortMappings = @()) {
  $output = @($RunArgs)
  if ($NetworkName) {
    $output += @("--network", $NetworkName, "--network-alias", $ServiceName)
  }
  $output += Get-ServiceEnvironmentArgs $Service
  if ($Service.working_dir) {
    $output += @("-w", [string]$Service.working_dir)
  }
  if ($Service.entrypoint) {
    $entrypointArgs = Get-ServiceCommandArgs $Service.entrypoint
    if ($entrypointArgs.Count -eq 1) {
      $output += @("--entrypoint", $entrypointArgs[0])
    }
  }
  $effectiveMappings = if ($PortMappings.Count -gt 0) { @($PortMappings) } else { @(Resolve-ServicePortMappings $Service) }
  foreach ($mapping in @($effectiveMappings)) {
    $output += @("-p", "$($mapping.HostIp):$($mapping.Published):$($mapping.Target)")
  }
  foreach ($volume in @($Service.volumes)) {
    if ($volume.type -eq "bind" -and $volume.source -and $volume.target) {
      $output += @("-v", "$($volume.source):$($volume.target)")
    }
  }
  return $output
}

function Start-SingleServiceWithDockerRun([string]$ComposeDir, [string]$RelativeName, [string]$LogFile) {
  $config = Get-ComposeConfig $ComposeDir
  $single = Get-SingleServiceFromComposeConfig $config
  if (-not $single -or -not $single.Service.image) {
    return $null
  }

  $safe = ($RelativeName -replace "[^A-Za-z0-9_.-]", "-").ToLowerInvariant()
  $containerName = "aegisprobe-vulhub-$safe"
  Run-LoggedCommand -File "docker" -CommandArgs @("rm", "-f", $containerName) -WorkDir $ComposeDir -LogFile $LogFile -TimeoutSeconds 30 | Out-Null

  $portMappings = @(Resolve-ServicePortMappings $single.Service)
  foreach ($mapping in @($portMappings | Where-Object Remapped)) {
    Add-Content -LiteralPath $LogFile -Value "PORT REMAP: service=$($single.Name) target=$($mapping.Target) requested=$($mapping.OriginalPublished) assigned=$($mapping.Published)"
  }
  $runArgs = Add-ServiceDockerRunArgs -RunArgs @("run", "-d", "--name", $containerName) -Service $single.Service -NetworkName "" -ServiceName $single.Name -PortMappings $portMappings
  $runArgs += [string]$single.Service.image
  $runArgs += Get-ServiceCommandArgs $single.Service.command
  $code = Run-LoggedCommand -File "docker" -CommandArgs $runArgs -WorkDir $ComposeDir -LogFile $LogFile -TimeoutSeconds 180
  if ($code -ne 0) {
    return $null
  }

  $publishers = @()
  foreach ($mapping in @($portMappings)) {
    $publishers += [pscustomobject]@{
      Service = $single.Name
      Image = [string]$single.Service.image
      Host = [string]$mapping.HostIp
      Port = [int]$mapping.Published
      TargetPort = [int]$mapping.Target
    }
  }

  return [pscustomobject]@{
    ContainerName = $containerName
    ContainerNames = @($containerName)
    NetworkName = $null
    Image = [string]$single.Service.image
    Images = @([string]$single.Service.image)
    Publishers = $publishers
  }
}

function Start-MultiServiceWithDockerRun([string]$ComposeDir, [string]$RelativeName, [string]$ComposeProject, [string]$LogFile) {
  $config = Get-ComposeConfig $ComposeDir
  if (-not $config -or -not $config.services) { return $null }
  $serviceNames = @($config.services.PSObject.Properties.Name)
  if ($serviceNames.Count -le 1) { return $null }

  $safe = ($RelativeName -replace "[^A-Za-z0-9_.-]", "-").ToLowerInvariant()
  $shortSafe = if ($safe.Length -gt 40) { $safe.Substring(0, 40).TrimEnd("-") } else { $safe }
  $networkName = "aegisprobe-vulhub-$($ComposeProject)-net"
  $containerNames = @()
  $images = @()
  foreach ($serviceName in $serviceNames) {
    $containerNames += "aegisprobe-vulhub-$shortSafe-$serviceName"
  }
  foreach ($containerName in $containerNames) {
    Run-LoggedCommand -File "docker" -CommandArgs @("rm", "-f", $containerName) -WorkDir $ComposeDir -LogFile $LogFile -TimeoutSeconds 30 | Out-Null
  }
  Run-LoggedCommand -File "docker" -CommandArgs @("network", "rm", $networkName) -WorkDir $ComposeDir -LogFile $LogFile -TimeoutSeconds 30 | Out-Null
  $networkCode = New-DockerRunNetwork $networkName $ComposeDir $LogFile
  if ($networkCode -ne 0) {
    return $null
  }

  $startedContainers = @()
  $publishers = @()
  foreach ($serviceName in @(Get-ComposeServiceStartOrder $config)) {
    $service = $config.services.$serviceName
    if (-not $service.image) {
      return $null
    }
    $containerName = "aegisprobe-vulhub-$shortSafe-$serviceName"
    $portMappings = @(Resolve-ServicePortMappings $service)
    foreach ($mapping in @($portMappings | Where-Object Remapped)) {
      Add-Content -LiteralPath $LogFile -Value "PORT REMAP: service=$serviceName target=$($mapping.Target) requested=$($mapping.OriginalPublished) assigned=$($mapping.Published)"
    }
    $runArgs = Add-ServiceDockerRunArgs -RunArgs @("run", "-d", "--name", $containerName) -Service $service -NetworkName $networkName -ServiceName $serviceName -PortMappings $portMappings
    $runArgs += [string]$service.image
    $runArgs += Get-ServiceCommandArgs $service.command
    $code = Run-LoggedCommand -File "docker" -CommandArgs $runArgs -WorkDir $ComposeDir -LogFile $LogFile -TimeoutSeconds 180
    if ($code -ne 0) {
      foreach ($started in $startedContainers) {
        Run-LoggedCommand -File "docker" -CommandArgs @("rm", "-f", $started) -WorkDir $ComposeDir -LogFile $LogFile -TimeoutSeconds 60 | Out-Null
      }
      Run-LoggedCommand -File "docker" -CommandArgs @("network", "rm", $networkName) -WorkDir $ComposeDir -LogFile $LogFile -TimeoutSeconds 30 | Out-Null
      return $null
    }
    $startedContainers += $containerName
    $images += [string]$service.image
    foreach ($mapping in @($portMappings)) {
      $publishers += [pscustomobject]@{
        Service = $serviceName
        Image = [string]$service.image
        Host = [string]$mapping.HostIp
        Port = [int]$mapping.Published
        TargetPort = [int]$mapping.Target
      }
    }
  }

  return [pscustomobject]@{
    ContainerName = $startedContainers[0]
    ContainerNames = $startedContainers
    NetworkName = $networkName
    Image = ($images | Select-Object -First 1)
    Images = @($images | Sort-Object -Unique)
    Publishers = $publishers
  }
}

function Test-HttpTarget([int]$Port) {
  $oldErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    foreach ($scheme in @("http", "https")) {
      $url = "${scheme}://127.0.0.1:$Port/"
      $args = @("-k", "-s", "-m", "8", "-o", "NUL", "-w", "%{http_code}", $url)
      $output = & curl.exe @args 2>$null
      if ($LASTEXITCODE -eq 0 -and $output -and $output -ne "000") {
        return $url
      }
    }
  } finally {
    $ErrorActionPreference = $oldErrorActionPreference
  }
  return $null
}

function Wait-HttpTarget([object[]]$Publishers, [int]$TimeoutSeconds) {
  $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(1, $TimeoutSeconds))
  do {
    foreach ($publisher in @($Publishers)) {
      $url = Test-HttpTarget $publisher.Port
      if ($url) {
        return $url
      }
    }
    Start-Sleep -Seconds 1
  } while ([DateTime]::UtcNow -lt $deadline)
  return $null
}

function Select-SmokePublishers([object[]]$Publishers, $SmokeCase) {
  $preferredPorts = @($SmokeCase.target.preferredPorts) | ForEach-Object {
    if ($_ -ne $null -and "$_".Trim()) { [int]$_ }
  }
  if ($preferredPorts.Count -eq 0) {
    return @($Publishers)
  }
  $selected = @($Publishers | Where-Object { $preferredPorts -contains [int]$_.Port -or $preferredPorts -contains [int]$_.TargetPort })
  if ($selected.Count -gt 0) {
    return $selected
  }
  return @($Publishers)
}

function Load-SmokeCases([string]$Path) {
  $resolved = Resolve-RepoPath $Path
  if (-not (Test-Path -LiteralPath $resolved)) {
    throw "Smoke case manifest not found: $resolved"
  }
  return (Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json).cases
}

function Normalize-LabPath([string]$Path) {
  return ($Path -replace "\\", "/").Trim("/").ToLowerInvariant()
}

function Find-SmokeCaseForLab([object[]]$Cases, [string]$RelativeName) {
  $relative = Normalize-LabPath $RelativeName
  foreach ($case in @($Cases)) {
    foreach ($hint in @($case.labPathHints)) {
      if (-not $hint) { continue }
      $normalizedHint = Normalize-LabPath ([string]$hint)
      if ($relative -eq $normalizedHint -or $relative.EndsWith("/$normalizedHint")) {
        return $case
      }
    }
  }
  return $null
}

$repoRoot = (Resolve-Path -LiteralPath ".").Path
$rootPath = Resolve-RepoPath $Root
$smokeCasesConfig = if ($UseSmokeHarness) { @(Load-SmokeCases $SmokeCases) } else { @() }
$runId = "$(Get-Date -Format 'yyyyMMdd-HHmmss-fff')-$PID"
$reportDir = Join-Path $repoRoot "data\vulhub-test-runs\$runId"
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$summaryPath = Join-Path $reportDir "summary.jsonl"
$composeFiles = Get-ChildItem -Path $rootPath -Recurse -File -Include docker-compose.yml,docker-compose.yaml,compose.yml,compose.yaml |
  Sort-Object FullName

if ($StartIndex -gt 0) {
  $composeFiles = $composeFiles | Select-Object -Skip $StartIndex
}

if ($MaxTargets -gt 0) {
  $composeFiles = $composeFiles | Select-Object -First $MaxTargets
}

$total = @($composeFiles).Count
Write-Host "Vulhub compose targets: $total"
Write-Host "Report directory: $reportDir"

for ($offset = 0; $offset -lt $total; $offset += $BatchSize) {
  $batch = @($composeFiles | Select-Object -Skip $offset -First $BatchSize)
  $batchNo = [int]([math]::Floor($offset / $BatchSize) + 1)
  Write-Host "Starting batch $batchNo with $($batch.Count) compose targets"

  foreach ($composeFile in $batch) {
    $composeDir = $composeFile.Directory.FullName
    $relativeName = $composeDir.Substring($rootPath.Length).TrimStart("\")
    if (-not $relativeName) {
      $relativeName = Split-Path -Leaf $composeDir
    }
    $safeName = ($relativeName -replace "[\\/:*?`"<>|]", "_")
    $composeProject = ("ca-$($runId.Substring(0, [Math]::Min(15, $runId.Length)))-$(Short-Hash $relativeName)" -replace "[^A-Za-z0-9_-]", "-").ToLowerInvariant()
    $targetLog = Join-Path $reportDir "$safeName.log"
    $agentLog = Join-Path $reportDir "$safeName.agent.log"
    $record = [ordered]@{
      target = $relativeName
      composeDir = $composeDir
      status = "unknown"
      httpTarget = $null
      ports = @()
      agentExitCode = $null
      startMode = "compose"
      startedAt = (Get-Date).ToString("o")
      endedAt = $null
      notes = @()
      smokeCaseId = $null
      smokeReport = $null
      smokeDb = $null
    }

    $dockerRunState = $null
    $containerSnapshot = Get-DockerContainerSnapshot
    $imageSnapshot = if ($RemoveImages) { Get-DockerImageSnapshot } else { $null }
    try {
      Write-Host "[$relativeName] up"
      if ($RequireLocalImages) {
        $missingImages = @(Get-MissingLocalImages $composeDir)
        if ($missingImages.Count -gt 0) {
          $record.status = "local_images_missing"
          $record.notes += "missing local images: $($missingImages -join ', ')"
          continue
        }
      }
      $upCode = 1
      $tryDockerRunFirst = $PreferDockerRun -or ((-not $DisableSingleServiceDockerRun) -and (Test-SingleServiceDockerRunCandidate $composeDir))
      if ($tryDockerRunFirst) {
        $dockerRunState = Start-SingleServiceWithDockerRun $composeDir $relativeName $targetLog
        if ($dockerRunState) {
          $upCode = 0
          $record.startMode = "docker_run"
        } elseif ($PreferDockerRun) {
          $dockerRunState = Start-MultiServiceWithDockerRun $composeDir $relativeName $composeProject $targetLog
          if ($dockerRunState) {
            $upCode = 0
            $record.startMode = "docker_run_multi"
          } else {
            $record.notes += "docker run preferred path was unavailable or failed; trying compose"
          }
        } else {
          $record.notes += "single-service docker run fast path was unavailable or failed; trying compose"
        }
      }

      if (-not $dockerRunState) {
        Run-LoggedCommand -File "docker" -CommandArgs (Compose-Args $composeProject @("down", "--volumes", "--remove-orphans")) -WorkDir $composeDir -LogFile $targetLog -TimeoutSeconds 90 | Out-Null
        $maxComposeAttempts = 3
        for ($attempt = 1; $attempt -le $maxComposeAttempts; $attempt += 1) {
          $upCode = Run-LoggedCommand -File "docker" -CommandArgs (Compose-Args $composeProject @("up", "-d")) -WorkDir $composeDir -LogFile $targetLog -TimeoutSeconds $ComposeUpTimeoutSeconds
          if ($upCode -eq 0) {
            break
          }
          if (Test-LogHasDockerMissingContainerError $targetLog) {
            $record.notes += "docker compose hit daemon missing-container create error; switching to docker run fallback"
            break
          }
          if ($attempt -lt $maxComposeAttempts) {
            $record.notes += "docker compose up attempt $attempt exited $upCode; retrying after cleanup"
            Run-LoggedCommand -File "docker" -CommandArgs (Compose-Args $composeProject @("down", "--volumes", "--remove-orphans")) -WorkDir $composeDir -LogFile $targetLog -TimeoutSeconds 90 | Out-Null
            Start-Sleep -Seconds (2 + $attempt)
          }
        }
      }

      if ($upCode -ne 0) {
        $record.status = "compose_up_failed"
        $record.notes += "docker compose up exited $upCode"
        $record.notes += "trying docker run fallback for compose services"
        Run-LoggedCommand -File "docker" -CommandArgs (Compose-Args $composeProject @("down", "--volumes", "--remove-orphans")) -WorkDir $composeDir -LogFile $targetLog -TimeoutSeconds 90 | Out-Null
        $dockerRunState = Start-SingleServiceWithDockerRun $composeDir $relativeName $targetLog
        if ($dockerRunState) {
          $record.status = "unknown"
          $record.startMode = "docker_run"
        } else {
          $dockerRunState = Start-MultiServiceWithDockerRun $composeDir $relativeName $composeProject $targetLog
          if ($dockerRunState) {
            $record.status = "unknown"
            $record.startMode = "docker_run_multi"
          }
        }
        if (-not $dockerRunState) {
          continue
        }
      }

      $publishers = if ($dockerRunState) { @($dockerRunState.Publishers) } else { @(Get-ComposePublishers $composeDir $composeProject) }
      $record.ports = @($publishers | ForEach-Object { "$($_.Host):$($_.Port)->$($_.TargetPort)/$($_.Service)" })
      if ($publishers.Count -eq 0) {
        $record.status = "no_published_tcp_port"
        continue
      }

      $smokeCase = if ($UseSmokeHarness) { Find-SmokeCaseForLab $smokeCasesConfig $relativeName } else { $null }
      if ($smokeCase) {
        $record.smokeCaseId = [string]$smokeCase.id
      }
      $targetPublishers = if ($smokeCase) { Select-SmokePublishers $publishers $smokeCase } else { @($publishers) }
      $record.httpTarget = Wait-HttpTarget $targetPublishers $HttpReadyTimeoutSeconds

      if (-not $record.httpTarget) {
        $record.status = "non_http_or_not_ready"
        continue
      }

      if ($SkipAgent) {
        $record.status = "http_ready_agent_skipped"
        continue
      }

      if ($smokeCase) {
        $record.smokeReport = Join-Path $reportDir "$safeName.agent-smoke.json"
        $record.smokeDb = Join-Path $reportDir "$safeName.agent-smoke.sqlite"
        Write-Host "[$relativeName] agent smoke $($record.smokeCaseId) $($record.httpTarget)"
        $agentArgs = @(
          "scripts\agent-lab-smoke.mjs",
          "--case", $record.smokeCaseId,
          "--target", $record.httpTarget,
          "--out", $record.smokeReport,
          "--db", $record.smokeDb
        )
        if ($SmokeActiveProof) {
          $agentArgs += "--active-proof"
        }
        $exitCode = Run-LoggedCommand -File "node" -CommandArgs $agentArgs -WorkDir $repoRoot -LogFile $agentLog -TimeoutSeconds $AgentTimeoutSeconds
        $record.agentExitCode = $exitCode
        $record.status = if ($exitCode -eq 0) { "agent_smoke_passed" } elseif ($exitCode -eq 124) { "agent_smoke_timeout" } else { "agent_smoke_failed" }
      } else {
        Write-Host "[$relativeName] agent $($record.httpTarget)"
        $agentArgs = @("apps\cli\dist\index.js", "pentest", $record.httpTarget, "--active", "--yes", "--rate", "5")
        $exitCode = Run-LoggedCommand -File "node" -CommandArgs $agentArgs -WorkDir $repoRoot -LogFile $agentLog -TimeoutSeconds $AgentTimeoutSeconds
        $record.agentExitCode = $exitCode
        $record.status = if ($exitCode -eq 0) { "agent_completed" } elseif ($exitCode -eq 124) { "agent_timeout" } else { "agent_failed" }
      }
    } catch {
      $record.status = "error"
      $record.notes += $_.Exception.Message
      Add-Content -LiteralPath $targetLog -Value $_.Exception.ToString()
    } finally {
      $record.endedAt = (Get-Date).ToString("o")
      $record | ConvertTo-Json -Compress -Depth 5 | Add-Content -LiteralPath $summaryPath
      Write-Host "[$relativeName] down and remove images"
      if ($dockerRunState) {
        foreach ($containerName in @($dockerRunState.ContainerNames)) {
          Run-LoggedCommand -File "docker" -CommandArgs @("rm", "-f", [string]$containerName) -WorkDir $composeDir -LogFile $targetLog -TimeoutSeconds 60 | Out-Null
        }
        if ($dockerRunState.NetworkName) {
          Run-LoggedCommand -File "docker" -CommandArgs @("network", "rm", [string]$dockerRunState.NetworkName) -WorkDir $composeDir -LogFile $targetLog -TimeoutSeconds 30 | Out-Null
        }
        if ($RemoveImages) {
          foreach ($image in @($dockerRunState.Images)) {
            Run-LoggedCommand -File "docker" -CommandArgs @("rmi", "-f", [string]$image) -WorkDir $composeDir -LogFile $targetLog -TimeoutSeconds 180 | Out-Null
          }
        }
      } else {
        $downArgs = Compose-Args $composeProject @("down", "--volumes", "--remove-orphans")
        if ($RemoveImages) {
          $downArgs += @("--rmi", "all")
        }
        Run-LoggedCommand -File "docker" -CommandArgs $downArgs -WorkDir $composeDir -LogFile $targetLog -TimeoutSeconds 180 | Out-Null
      }
      Remove-NewDockerContainers $containerSnapshot $composeDir $targetLog
      if ($RemoveImages) {
        Remove-NewDockerImages $imageSnapshot $composeDir $targetLog
      }
    }
  }
}

Write-Host "Summary: $summaryPath"
