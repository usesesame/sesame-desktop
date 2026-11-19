[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$InstallerPath,

  [string]$EvidenceRoot = (Join-Path ([System.IO.Path]::GetTempPath()) 'sesame-command-line-install-evidence'),

  [switch]$AllowMachinePathChanges
)

$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -and -not $AllowMachinePathChanges) {
  throw 'This test rewrites the machine Path many times. Run it in CI, or on a throwaway machine with -AllowMachinePathChanges.'
}
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'This test installs Sesame for the whole machine, so it must run as an administrator.'
}

$environmentKeyPath = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'

function Read-PathValue {
  param([Microsoft.Win32.RegistryKey]$Hive, [string]$KeyPath)
  $key = $Hive.OpenSubKey($KeyPath, $false)
  if ($null -eq $key) {
    return [pscustomobject][ordered]@{ Exists = $false; Kind = ''; Length = 0; Value = '' }
  }
  try {
    if (-not ($key.GetValueNames() -contains 'Path')) {
      return [pscustomobject][ordered]@{ Exists = $false; Kind = ''; Length = 0; Value = '' }
    }
    $raw = $key.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $value = if ($raw -is [string[]]) { $raw -join "`n" } else { [string]$raw }
    return [pscustomobject][ordered]@{ Exists = $true; Kind = $key.GetValueKind('Path').ToString(); Length = $value.Length; Value = $value }
  } finally {
    $key.Close()
  }
}

function Get-MachinePath { Read-PathValue ([Microsoft.Win32.Registry]::LocalMachine) $environmentKeyPath }
function Get-UserPath { Read-PathValue ([Microsoft.Win32.Registry]::CurrentUser) 'Environment' }

function Set-MachinePath {
  param([string]$Value, [string]$Kind)
  $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($environmentKeyPath, $true)
  try {
    if ($Kind -eq 'MultiString') {
      $key.SetValue('Path', [string[]]$Value.Split([char]"`n"), [Microsoft.Win32.RegistryValueKind]::MultiString)
    } else {
      $key.SetValue('Path', $Value, [Microsoft.Win32.RegistryValueKind]$Kind)
    }
  } finally {
    $key.Close()
  }
  $written = Get-MachinePath
  if ($written.Kind -ne $Kind -or -not [string]::Equals($written.Value, $Value, [StringComparison]::Ordinal)) {
    throw "The machine Path could not be set. Expected $Kind with $($Value.Length) characters, found $($written.Kind) with $($written.Length) characters."
  }
}

$originalPath = Get-MachinePath
$originalUserPath = Get-UserPath
if (-not $originalPath.Exists) {
  throw 'The machine has no Path value, so this test would have nothing to restore.'
}
if ($originalPath.Kind -ne 'String' -and $originalPath.Kind -ne 'ExpandString') {
  throw "The machine Path is of type $($originalPath.Kind), which this test cannot restore safely."
}

$productName = 'Sesame'
$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$installDirectory = Join-Path $env:ProgramFiles $productName
$terminalFolder = Join-Path $installDirectory 'cli'
$terminalProgram = Join-Path $terminalFolder 'sesame.exe'
$desktopProgram = Join-Path $installDirectory 'sesame.exe'
$uninstaller = Join-Path $installDirectory 'uninstall.exe'
$browserHost = Join-Path $installDirectory 'sesame-browser-host.exe'
$chromeHostKey = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\app.usesesame.browser'
$commandShell = Join-Path $env:SystemRoot 'System32\cmd.exe'
$ownerValueName = 'TerminalPathAdded'
$statusValueName = 'TerminalPathStatus'
$statusChanged = '0'
$statusUnchanged = '10'
$statusRefused = 11
$statusFailed = '12'
$environmentLimit = 32767
$commandShellLineLimit = 8191
$uninstallKeys = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$productName",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$productName"
)
$diagnosticsFile = Join-Path $env:LOCALAPPDATA 'app.usesesame.desktop\logs\sesame-diagnostics.jsonl'
$collector = Join-Path $PSScriptRoot 'collect-installer-lifecycle-evidence.ps1'

$exitOk = 0
$exitUnreachable = 3
$exitTimeout = 4
$notRunningMessage = 'Sesame is not running. Open Sesame and try again.'
$unlockWaitingMessage = 'Unlock Sesame to continue.'
$timeoutMessage = 'Nobody answered in Sesame.'
$unlockWaitSeconds = 120
$clientDeadlineSeconds = 200
$requestLimitSeconds = 215
$listenerWaitSeconds = 90
$basePath = '%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SystemRoot%\System32\WindowsPowerShell\v1.0\;C:\Fictional Tools\bin'

New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
$workDirectory = Join-Path $EvidenceRoot 'empty-working-folder'
New-Item -ItemType Directory -Force -Path $workDirectory | Out-Null

$script:failures = New-Object 'System.Collections.Generic.List[string]'
$script:scenario = 'setup'
$script:evidenceIndex = 0
$script:scenarioCount = 0

function Save-Evidence {
  param([string]$Name, $Data)
  $slug = ("$script:scenario $Name" -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant()
  if ($slug.Length -gt 120) { $slug = $slug.Substring(0, 120) }
  $file = Join-Path $EvidenceRoot ('{0:D3}-{1}.json' -f $script:evidenceIndex, $slug)
  $script:evidenceIndex++
  $Data | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $file -Encoding UTF8
}

Save-Evidence 'original paths' ([ordered]@{ machinePath = $originalPath; userPath = $originalUserPath })

function Format-PathValue {
  param($State)
  if (-not $State.Exists) { return 'no Path value' }
  return "$($State.Kind) with $($State.Length) characters [$($State.Value)]"
}

function Confirm-That {
  param([string]$What, [bool]$Condition, [string]$Expected, [string]$Found)
  if ($Condition) {
    Write-Host "ok: $What"
    return
  }
  $message = "[$script:scenario] $What. Expected $Expected, found $Found."
  Write-Host "::error::$message"
  $script:failures.Add($message)
}

function Add-Failure {
  param([string]$Message)
  $line = "[$script:scenario] $Message"
  Write-Host "::error::$line"
  $script:failures.Add($line)
}

function Invoke-Installer {
  param([string]$Path, [string[]]$Arguments)
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $process = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru
  $null = $process.Handle
  if (-not $process.WaitForExit(300000)) {
    $process.Kill()
    throw "$Path $Arguments did not finish within 5 minutes."
  }
  Write-Host ("ran: {0} {1} in {2:N1} seconds, exit code {3}" -f (Split-Path -Leaf $Path), ($Arguments -join ' '), $watch.Elapsed.TotalSeconds, $process.ExitCode)
  return $process.ExitCode
}

function Install-Sesame {
  param([string[]]$Arguments)
  $code = Invoke-Installer $installer $Arguments
  Confirm-That "the installer with $($Arguments -join ' ') exits 0" ($code -eq 0) '0' "$code"
}

function Uninstall-Sesame {
  param([string[]]$Arguments)
  $code = Invoke-Installer $uninstaller (@($Arguments) + "_?=$installDirectory")
  Confirm-That "the uninstaller with $($Arguments -join ' ') exits 0" ($code -eq 0) '0' "$code"
}

function Get-UninstallKey {
  foreach ($key in $uninstallKeys) {
    if (Test-Path -LiteralPath $key) { return $key }
  }
  return $null
}

function Get-ProductValue {
  param([string]$Name)
  foreach ($root in 'HKLM:\SOFTWARE\WOW6432Node', 'HKLM:\SOFTWARE') {
    foreach ($vendor in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
      $candidate = Join-Path $vendor.PSPath $productName
      if (-not (Test-Path -LiteralPath $candidate)) { continue }
      $value = (Get-Item -LiteralPath $candidate).GetValue($Name)
      if ($null -ne $value) {
        return [pscustomobject][ordered]@{ Key = $candidate; Value = [string]$value }
      }
    }
  }
  return $null
}

function Get-PathRecord { Get-ProductValue $ownerValueName }
function Get-PathStatus { Get-ProductValue $statusValueName }

function Get-InstalledProcesses {
  $prefix = $installDirectory + '\'
  @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
      $path = $null
      try { $path = $_.Path } catch { $path = $null }
      $path -and $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    })
}

function Get-DesktopProcesses {
  @(Get-InstalledProcesses | Where-Object { $_.Path -ieq $desktopProgram })
}

function Stop-InstalledProcesses {
  foreach ($process in Get-InstalledProcesses) {
    Write-Host "stopping $($process.Path) with id $($process.Id)"
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    $null = $process.WaitForExit(15000)
  }
}

function Test-TerminalEntry {
  param([string]$Entry)
  return ($Entry -ieq $terminalFolder) -or ($Entry -ieq "$terminalFolder\")
}

function Get-PathEntries {
  param([string]$Value)
  return , ([string[]]$Value.Split([char]';'))
}

function Test-SameEntries {
  param([string[]]$Expected, [string[]]$Actual)
  if ($Expected.Count -ne $Actual.Count) { return $false }
  for ($index = 0; $index -lt $Expected.Count; $index++) {
    if (-not [string]::Equals($Expected[$index], $Actual[$index], [StringComparison]::Ordinal)) { return $false }
  }
  return $true
}

function Get-PathWithTerminal {
  param([string]$Value)
  if ($Value.EndsWith(';')) { return "$Value$terminalFolder;" }
  return "$Value;$terminalFolder"
}

function Get-State {
  param([string]$Step)
  $state = [pscustomobject][ordered]@{
    step = $Step
    machinePath = Get-MachinePath
    userPath = Get-UserPath
    terminalPathRecord = Get-PathRecord
    terminalPathStatus = Get-PathStatus
    uninstallKey = Get-UninstallKey
    terminalProgramExists = Test-Path -LiteralPath $terminalProgram
    terminalFolderExists = Test-Path -LiteralPath $terminalFolder
  }
  Write-Host "state $Step"
  Write-Host "  machine Path: $(Format-PathValue $state.machinePath)"
  if ($state.terminalPathRecord) {
    Write-Host "  record of the added entry: $($state.terminalPathRecord.Value) under $($state.terminalPathRecord.Key)"
  } else {
    Write-Host '  record of the added entry: none'
  }
  if ($state.terminalPathStatus) {
    Write-Host "  outcome of the Path edit at install: $($state.terminalPathStatus.Value)"
  } else {
    Write-Host '  outcome of the Path edit at install: none recorded'
  }
  Write-Host "  cli\sesame.exe present: $($state.terminalProgramExists), cli folder present: $($state.terminalFolderExists)"
  Save-Evidence $Step $state
  return $state
}

function Save-LifecycleEvidence {
  param([string]$Label)
  try {
    $output = & $collector -Label $Label -OutputRoot (Join-Path $EvidenceRoot 'lifecycle') -InstallerPath $installer
    Write-Host "lifecycle evidence: $output"
  } catch {
    Add-Failure "the lifecycle evidence collector failed at $Label with $($_.Exception.Message)"
  }
}

function Confirm-PathUnchanged {
  param([string]$What, $Expected, $Actual)
  Confirm-That "$What keeps the Path type" ($Actual.Kind -eq $Expected.Kind) $Expected.Kind $Actual.Kind
  $same = $Actual.Exists -and [string]::Equals($Expected.Value, $Actual.Value, [StringComparison]::Ordinal)
  Confirm-That "$What leaves Path byte for byte as it was" $same (Format-PathValue $Expected) (Format-PathValue $Actual)
}

function Confirm-TerminalAdded {
  param([string]$What, $Before, $After)
  $entries = Get-PathEntries $After.Value
  $matching = @($entries | Where-Object { Test-TerminalEntry $_ })
  Confirm-That "$What leaves exactly one Path entry for $terminalFolder" ($matching.Count -eq 1) '1 entry' "$($matching.Count) entries [$($matching -join ' | ')]"
  Confirm-That "$What adds the entry as $terminalFolder" ($entries -ccontains $terminalFolder) $terminalFolder ($matching -join ' | ')
  $others = [string[]]@($entries | Where-Object { -not (Test-TerminalEntry $_) })
  $earlier = [string[]]@((Get-PathEntries $Before.Value) | Where-Object { -not (Test-TerminalEntry $_) })
  Confirm-That "$What keeps every other Path entry byte for byte and in order" (Test-SameEntries $earlier $others) "[$($earlier -join ';')]" "[$($others -join ';')]"
  $expected = Get-PathWithTerminal $Before.Value
  Confirm-That "$What appends the entry and changes nothing else" ([string]::Equals($expected, $After.Value, [StringComparison]::Ordinal)) "[$expected]" "[$($After.Value)]"
  Confirm-That "$What keeps the Path type" ($After.Kind -eq $Before.Kind) $Before.Kind $After.Kind
}

function Confirm-RecordAdded {
  param([string]$What, $State)
  $found = if ($State.terminalPathRecord) { $State.terminalPathRecord.Value } else { 'no record' }
  Confirm-That "$What records the entry Sesame added" ($found -ceq $terminalFolder) $terminalFolder $found
}

function Confirm-Status {
  param([string]$What, $State, [string]$Expected)
  $found = if ($State.terminalPathStatus) { $State.terminalPathStatus.Value } else { 'no outcome recorded' }
  Confirm-That "$What records the outcome of the Path edit" ($found -ceq $Expected) $Expected $found
}

function Confirm-NoRecord {
  param([string]$What, $State)
  $found = if ($State.terminalPathRecord) { $State.terminalPathRecord.Value } else { 'no record' }
  Confirm-That "$What records no Path entry as added by Sesame" ($null -eq $State.terminalPathRecord) 'no record' $found
}

function Confirm-Unexpanded {
  param([string]$What, $State)
  Confirm-That "$What keeps %SystemRoot% unexpanded in Path" ($State.machinePath.Value.Contains('%SystemRoot%\system32;%SystemRoot%;')) '%SystemRoot%\system32;%SystemRoot%;' (Format-PathValue $State.machinePath)
}

function Confirm-TerminalRemoved {
  param([string]$What, $State)
  Confirm-That "$What removes cli\sesame.exe" (-not $State.terminalProgramExists) 'no file' $terminalProgram
  Confirm-That "$What removes the cli folder" (-not $State.terminalFolderExists) 'no folder' $terminalFolder
  Confirm-That "$What removes the uninstall key" ($null -eq $State.uninstallKey) 'no key' "$($State.uninstallKey)"
  Confirm-NoRecord $What $State
}

function Get-PeSubsystem {
  param([string]$Path)
  $bytes = [IO.File]::ReadAllBytes($Path)
  $offset = [BitConverter]::ToInt32($bytes, 0x3C)
  if ($offset -lt 0 -or $offset + 96 -gt $bytes.Length -or $bytes[$offset] -ne 0x50 -or $bytes[$offset + 1] -ne 0x45 -or $bytes[$offset + 2] -ne 0 -or $bytes[$offset + 3] -ne 0) {
    return 'not a Windows executable'
  }
  switch ([BitConverter]::ToUInt16($bytes, $offset + 24 + 68)) {
    2 { return 'windows' }
    3 { return 'console' }
    default { return "subsystem $_" }
  }
}

function Confirm-InstalledPrograms {
  Confirm-That 'cli\sesame.exe is installed under the install folder' (Test-Path -LiteralPath $terminalProgram) $terminalProgram 'no file'
  Confirm-That 'the desktop sesame.exe is installed' (Test-Path -LiteralPath $desktopProgram) $desktopProgram 'no file'
  if (-not (Test-Path -LiteralPath $terminalProgram) -or -not (Test-Path -LiteralPath $desktopProgram)) { return }
  $terminalKind = Get-PeSubsystem $terminalProgram
  $desktopKind = Get-PeSubsystem $desktopProgram
  $terminalHash = (Get-FileHash -LiteralPath $terminalProgram -Algorithm SHA256).Hash
  $desktopHash = (Get-FileHash -LiteralPath $desktopProgram -Algorithm SHA256).Hash
  Write-Host "cli\sesame.exe: $terminalKind program, SHA256 $terminalHash, $((Get-Item -LiteralPath $terminalProgram).Length) bytes"
  Write-Host "sesame.exe: $desktopKind program, SHA256 $desktopHash, $((Get-Item -LiteralPath $desktopProgram).Length) bytes"
  Save-Evidence 'installed programs' ([ordered]@{
      terminalProgram = $terminalProgram; terminalSubsystem = $terminalKind; terminalSha256 = $terminalHash
      desktopProgram = $desktopProgram; desktopSubsystem = $desktopKind; desktopSha256 = $desktopHash
    })
  Confirm-That 'cli\sesame.exe is a console program' ($terminalKind -eq 'console') 'console' $terminalKind
  Confirm-That 'the desktop sesame.exe is a windowed program' ($desktopKind -eq 'windows') 'windows' $desktopKind
  Confirm-That 'cli\sesame.exe is a different file from the desktop' ($terminalHash -ne $desktopHash) 'two different hashes' "both $terminalHash"
}

function Get-NewSessionPath {
  $parts = @()
  foreach ($state in @((Get-MachinePath), (Get-UserPath))) {
    if (-not $state.Exists -or $state.Value -eq '') { continue }
    if ($state.Kind -eq 'ExpandString') {
      $parts += [Environment]::ExpandEnvironmentVariables($state.Value)
    } else {
      $parts += $state.Value
    }
  }
  return ($parts -join ';')
}

function Stop-TerminalPrograms {
  foreach ($process in @(Get-InstalledProcesses | Where-Object { $_.Path -ieq $terminalProgram })) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-Captured {
  param([string]$FilePath, [string]$Arguments, [int]$TimeoutSeconds, [string]$PathValue)
  $info = New-Object System.Diagnostics.ProcessStartInfo
  $info.FileName = $FilePath
  $info.Arguments = $Arguments
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  $info.RedirectStandardInput = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.StandardOutputEncoding = [Text.Encoding]::UTF8
  $info.StandardErrorEncoding = [Text.Encoding]::UTF8
  $info.WorkingDirectory = $workDirectory
  if ($PSBoundParameters.ContainsKey('PathValue')) {
    $info.EnvironmentVariables['Path'] = $PathValue
  }
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $process = [Diagnostics.Process]::Start($info)
  $process.StandardInput.Close()
  $output = $process.StandardOutput.ReadToEndAsync()
  $errors = $process.StandardError.ReadToEndAsync()
  $finished = $process.WaitForExit($TimeoutSeconds * 1000)
  if ($finished) {
    $process.WaitForExit()
  } else {
    try { $process.Kill() } catch { Write-Host "could not stop $FilePath $($_.Exception.Message)" }
    Stop-TerminalPrograms
  }
  $watch.Stop()
  $exitCode = $null
  if ($finished) { $exitCode = $process.ExitCode }
  $outputText = ''
  if ($output.Wait(15000)) { $outputText = $output.Result }
  $errorText = ''
  if ($errors.Wait(15000)) { $errorText = $errors.Result }
  $result = [pscustomobject][ordered]@{
    command = "$FilePath $Arguments"
    finished = $finished
    exitCode = $exitCode
    seconds = [math]::Round($watch.Elapsed.TotalSeconds, 1)
    output = $outputText
    errors = $errorText
  }
  Write-Host "ran: $($result.command) in $($result.seconds) seconds, finished $finished, exit code $exitCode"
  Write-Host "  standard output: [$outputText]"
  Write-Host "  standard error: [$errorText]"
  return $result
}

function Invoke-SessionCommand {
  param([string]$Command, [int]$TimeoutSeconds, [string]$SessionPath)
  $result = Invoke-Captured $commandShell "/d /c $Command" $TimeoutSeconds $SessionPath
  Save-Evidence "ran $Command" $result
  return $result
}

function Confirm-PathModeRefusals {
  param($Expected)
  $copyFolder = Join-Path $EvidenceRoot 'copied-cli\cli'
  New-Item -ItemType Directory -Force -Path $copyFolder | Out-Null
  $copy = Join-Path $copyFolder 'sesame.exe'
  Copy-Item -LiteralPath $terminalProgram -Destination $copy -Force
  $copied = Invoke-Captured $copy '--add-to-machine-path' 30
  Remove-Item -LiteralPath (Join-Path $EvidenceRoot 'copied-cli') -Recurse -Force -ErrorAction SilentlyContinue
  Save-Evidence 'copied cli asked to add itself' $copied
  Confirm-That 'a copy of the cli program outside the install folder refuses to change Path' ($copied.exitCode -eq $statusRefused) "$statusRefused" "$($copied.exitCode)"
  Confirm-That 'the refusal names the installed copy' ($copied.errors.Contains('Only the copy of sesame.exe installed at')) 'a message naming the installed copy' "[$($copied.errors)]"
  Confirm-PathUnchanged 'a refused copy' $Expected (Get-MachinePath)

  $extra = Invoke-Captured $terminalProgram "--add-to-machine-path C:\Fictional\Elsewhere" 30
  Save-Evidence 'cli asked to add a folder from its arguments' $extra
  Confirm-That 'the cli program refuses a folder in its arguments' ($extra.exitCode -eq $statusRefused) "$statusRefused" "$($extra.exitCode)"
  Confirm-PathUnchanged 'a refused extra argument' $Expected (Get-MachinePath)

  $probeFolder = Join-Path $EvidenceRoot 'unelevated-probe'
  New-Item -ItemType Directory -Force -Path $probeFolder | Out-Null
  $probe = Join-Path $probeFolder 'probe.cmd'
  $exitFile = Join-Path $probeFolder 'exit.txt'
  $errorFile = Join-Path $probeFolder 'errors.txt'
  Set-Content -LiteralPath $probe -Encoding ASCII -Value @(
    '@echo off',
    "`"$terminalProgram`" --remove-from-machine-path 2> `"$errorFile`"",
    ">`"$exitFile`" echo %ERRORLEVEL%"
  )
  $runas = Invoke-Captured (Join-Path $env:SystemRoot 'System32\runas.exe') "/trustlevel:0x20000 `"$env:SystemRoot\System32\cmd.exe /d /c $probe`"" 30
  $watch = [Diagnostics.Stopwatch]::StartNew()
  while (-not (Test-Path -LiteralPath $exitFile) -and $watch.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Milliseconds 500 }
  Start-Sleep -Milliseconds 500
  $exitText = if (Test-Path -LiteralPath $exitFile) { (Get-Content -LiteralPath $exitFile -Raw).Trim() } else { 'no exit code, runas output was ' + $runas.output + $runas.errors }
  $errorText = if (Test-Path -LiteralPath $errorFile) { (Get-Content -LiteralPath $errorFile -Raw) } else { '' }
  Write-Host "a non-elevated run exited [$exitText] and printed [$errorText]"
  Save-Evidence 'non-elevated cli asked to remove its entry' ([ordered]@{ runas = $runas; exit = $exitText; errors = $errorText })
  Confirm-That 'a non-elevated run of the cli program refuses to change Path' ($exitText -eq "$statusRefused") "$statusRefused" $exitText
  Confirm-That 'the non-elevated refusal says an administrator is needed' ($errorText.Contains('running as an administrator')) 'a message about administrator rights' "[$errorText]"
  Confirm-PathUnchanged 'a refused non-elevated run' $Expected (Get-MachinePath)
}

function Confirm-ToolFromNewSession {
  param([string]$Version)
  $sessionPath = Get-NewSessionPath
  Write-Host "Path of a new session built from the registry: [$sessionPath]"
  Save-Evidence 'new session path' ([ordered]@{ path = $sessionPath })
  Confirm-That 'no Sesame desktop runs before the command runs' ((Get-DesktopProcesses).Count -eq 0) 'no desktop process' "$((Get-DesktopProcesses).Count) processes"

  $where = Invoke-SessionCommand 'where sesame' 30 $sessionPath
  $found = @($where.output -split "`r?`n" | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_.Trim() })
  $first = if ($found.Count -gt 0) { $found[0] } else { 'nothing' }
  Confirm-That 'a new session finds cli\sesame.exe first on Path' ($first -ieq $terminalProgram) $terminalProgram $first
  Confirm-That 'a new session never finds the desktop sesame.exe on Path' (-not ($found -icontains $desktopProgram)) 'no desktop match' ($found -join ' | ')

  $help = Invoke-SessionCommand 'sesame --help' 30 $sessionPath
  Confirm-That 'sesame --help exits 0' ($help.exitCode -eq $exitOk) "$exitOk" "$($help.exitCode)"
  $usage = $help.output.Contains('Usage:') -and $help.output.Contains('sesame list') -and $help.output.Contains('Exit codes:') -and $help.output.Contains('On Windows every request asks in the Sesame window')
  Confirm-That 'sesame --help does not list the installer arguments' (-not $help.output.Contains('machine-path')) 'no machine-path argument' "[$($help.output)]"
  Confirm-That 'sesame --help prints the Windows usage and exit codes' $usage 'Usage:, sesame list, Exit codes: and the Windows line' "[$($help.output)]"

  $versionRun = Invoke-SessionCommand 'sesame --version' 30 $sessionPath
  Confirm-That 'sesame --version exits 0' ($versionRun.exitCode -eq $exitOk) "$exitOk" "$($versionRun.exitCode)"
  Confirm-That 'sesame --version prints the installed version' ($versionRun.output.Trim() -ceq "sesame $Version") "sesame $Version" "[$($versionRun.output.Trim())]"

  $list = Invoke-SessionCommand 'sesame list' 60 $sessionPath
  Confirm-That 'sesame list without the desktop exits with the unreachable code' ($list.exitCode -eq $exitUnreachable) "$exitUnreachable" "$($list.exitCode)"
  Confirm-That 'sesame list without the desktop says Sesame is not running' ($list.errors.Contains($notRunningMessage)) $notRunningMessage "[$($list.errors)]"
  Start-Sleep -Seconds 2
  Confirm-That 'sesame list does not start the desktop' ((Get-DesktopProcesses).Count -eq 0) 'no desktop process' "$((Get-DesktopProcesses).Count) processes"
  return $sessionPath
}

function Test-TerminalPipe {
  try {
    return @([IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -like '*\Sesame.Cli.*' }).Count -gt 0
  } catch {
    return $false
  }
}

function Get-ListenerEvents {
  param([string]$Code)
  if (-not (Test-Path -LiteralPath $diagnosticsFile)) { return 0 }
  try {
    return @(Get-Content -LiteralPath $diagnosticsFile | Where-Object { $_.Contains('"operation":"terminal"') -and $_.Contains("`"code`":`"$Code`"") }).Count
  } catch {
    return 0
  }
}

function Save-Diagnostics {
  if (Test-Path -LiteralPath $diagnosticsFile) {
    $text = ''
    try { $text = Get-Content -LiteralPath $diagnosticsFile -Raw } catch { $text = "unreadable: $($_.Exception.Message)" }
    Write-Host "desktop diagnostics: [$text]"
    Save-Evidence 'desktop diagnostics' ([ordered]@{ file = $diagnosticsFile; content = $text })
  } else {
    Write-Host "desktop diagnostics: no file at $diagnosticsFile"
  }
}

function Confirm-ToolReachesDesktop {
  param([string]$SessionPath)
  if (Test-TerminalPipe) {
    Add-Failure 'a Sesame.Cli pipe already exists before the installed desktop starts'
    return
  }
  $startedBefore = Get-ListenerEvents 'pipe_server_started'
  $failedBefore = (Get-ListenerEvents 'pipe_server_failed') + (Get-ListenerEvents 'pipe_served_elsewhere')
  $desktop = Start-Process -FilePath $desktopProgram -WorkingDirectory $installDirectory -PassThru
  $null = $desktop.Handle
  try {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $listening = $false
    $signal = ''
    while ($watch.Elapsed.TotalSeconds -lt $listenerWaitSeconds) {
      if (Test-TerminalPipe) { $listening = $true; $signal = 'the Sesame.Cli pipe is listed'; break }
      if ((Get-ListenerEvents 'pipe_server_started') -gt $startedBefore) { $listening = $true; $signal = 'the desktop logged pipe_server_started'; break }
      if (((Get-ListenerEvents 'pipe_server_failed') + (Get-ListenerEvents 'pipe_served_elsewhere')) -gt $failedBefore) { $signal = 'the desktop logged that its terminal listener failed'; break }
      if ($desktop.HasExited) { $signal = "the desktop exited with code $($desktop.ExitCode)"; break }
      Start-Sleep -Milliseconds 500
    }
    if ($signal -eq '') { $signal = "no listener after $listenerWaitSeconds seconds" }
    $found = "$signal after $([math]::Round($watch.Elapsed.TotalSeconds, 1)) seconds"
    Write-Host "desktop listener: $found"
    Confirm-That 'the installed desktop starts and opens its terminal pipe' $listening 'a Sesame.Cli pipe' $found
    if (-not $listening) { return }

    $list = Invoke-SessionCommand 'sesame list' $requestLimitSeconds $SessionPath
    Confirm-That 'sesame list ends within the bounded wait' $list.finished "an exit within $requestLimitSeconds seconds" 'a process that was still waiting'
    Confirm-That 'sesame list with a locked desktop ends with the timeout code' ($list.exitCode -eq $exitTimeout) "$exitTimeout" "$($list.exitCode)"
    Confirm-That 'sesame list reaches the desktop and waits for an unlock' ($list.errors.Contains($unlockWaitingMessage)) $unlockWaitingMessage "[$($list.errors)]"
    Confirm-That 'sesame list says nobody answered' ($list.errors.Contains($timeoutMessage)) $timeoutMessage "[$($list.errors)]"
    $waitedForDesktop = ($list.seconds -ge ($unlockWaitSeconds - 5)) -and ($list.seconds -lt ($clientDeadlineSeconds - 10))
    Confirm-That 'sesame list waits for the desktop unlock deadline and not its own deadline' $waitedForDesktop "between $($unlockWaitSeconds - 5) and $($clientDeadlineSeconds - 10) seconds" "$($list.seconds) seconds"
    Confirm-That 'the desktop is still running after the request' (-not $desktop.HasExited) 'a running desktop' "exit code $(if ($desktop.HasExited) { $desktop.ExitCode })"
  } finally {
    Save-Diagnostics
    Stop-InstalledProcesses
  }
}

function Reset-Install {
  Stop-InstalledProcesses
  if ((Get-UninstallKey) -or (Get-PathRecord)) {
    if (-not (Get-UninstallKey) -or -not (Test-Path -LiteralPath $uninstaller) -or -not (Test-Path -LiteralPath $desktopProgram)) {
      $code = Invoke-Installer $installer @('/S')
      if ($code -ne 0) { Add-Failure "the cleanup install exited $code" }
    }
    $code = Invoke-Installer $uninstaller @('/S', "_?=$installDirectory")
    if ($code -ne 0) { Add-Failure "the cleanup uninstall exited $code" }
  }
  Remove-Item -LiteralPath $installDirectory -Recurse -Force -ErrorAction SilentlyContinue
  $record = Get-PathRecord
  if ($record) {
    Add-Failure "the record $($record.Value) was still under $($record.Key) after the cleanup uninstall"
    Remove-ItemProperty -LiteralPath $record.Key -Name $ownerValueName -ErrorAction SilentlyContinue
  }
}

function Wait-UninstallCopy {
  $temp = [IO.Path]::GetFullPath($env:TEMP)
  $watch = [Diagnostics.Stopwatch]::StartNew()
  while ($watch.Elapsed.TotalSeconds -lt 120) {
    $copies = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $path = $null
        try { $path = $_.Path } catch { $path = $null }
        $path -and $path.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase) -and ((Split-Path -Leaf $path) -like 'Un_*.exe')
      })
    if ($copies.Count -eq 0) { return [math]::Round($watch.Elapsed.TotalSeconds, 1) }
    Start-Sleep -Milliseconds 500
  }
  throw 'The temporary uninstaller copy was still running after 120 seconds.'
}

function Register-BrowserHost {
  $code = Invoke-Installer $browserHost @('register')
  Confirm-That 'the browser host registers itself' (($code -eq 0) -and (Test-Path -LiteralPath $chromeHostKey)) 'exit 0 and a Chrome registration' "exit $code, registered $(Test-Path -LiteralPath $chromeHostKey)"
}

function Invoke-Scenario {
  param([string]$ScenarioName, [string]$StartValue, [string]$StartKind, [scriptblock]$Body)
  $script:scenario = $ScenarioName
  $script:scenarioCount++
  Write-Host ''
  Write-Host "== $ScenarioName"
  try {
    if (Get-UninstallKey) { throw 'Sesame is still installed from an earlier step, so this scenario cannot start clean.' }
    if (Get-PathRecord) { throw 'A record of an added Path entry is left from an earlier step, so this scenario cannot start clean.' }
    if (Test-Path -LiteralPath $terminalFolder) { throw "$terminalFolder is left from an earlier step, so this scenario cannot start clean." }
    Set-MachinePath $StartValue $StartKind
    & $Body
  } catch {
    Add-Failure "the scenario stopped early: $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)"
  } finally {
    try {
      Reset-Install
    } catch {
      Add-Failure "the cleanup failed: $($_.Exception.Message)"
    }
    Set-MachinePath $originalPath.Value $originalPath.Kind
  }
}

function Get-LongPath {
  param([int]$Length)
  $prefix = "$basePath;C:\Fictional\Long\"
  return $prefix + ('x' * ($Length - $prefix.Length))
}

function Get-LongPathExpandedTo {
  param([int]$Expanded)
  $prefix = "$basePath;C:\Fictional\Long\"
  $growth = $prefix.Length - [Environment]::ExpandEnvironmentVariables($prefix).Length
  $value = Get-LongPath ($Expanded + $growth)
  $length = [Environment]::ExpandEnvironmentVariables($value).Length
  if ($length -ne $Expanded) { throw "The long Path expands to $length characters instead of $Expanded." }
  return $value
}

function Get-MachineSessionPath {
  param($State)
  return [Environment]::ExpandEnvironmentVariables($State.machinePath.Value)
}

function Confirm-LookupFromNewCommandShell {
  param([string]$What, [string]$SessionPath = (Get-NewSessionPath), [switch]$WithoutTool)
  $sessionPath = $SessionPath
  if (-not $WithoutTool) {
    $tool = Invoke-SessionCommand 'sesame --version' 30 $sessionPath
    $toolFound = ($tool.exitCode -eq $exitOk) -and $tool.output.StartsWith('sesame ')
    Confirm-That "$What lets a new cmd.exe with a Path of $($sessionPath.Length) characters run sesame" $toolFound 'sesame --version exits 0' "exit code $($tool.exitCode), output [$($tool.output)], errors [$($tool.errors)]"
  }
  $existing = Invoke-SessionCommand 'whoami' 30 $sessionPath
  Confirm-That "$What lets a new cmd.exe with a Path of $($sessionPath.Length) characters run a command from an existing entry" ($existing.exitCode -eq 0) 'whoami exits 0' "exit code $($existing.exitCode), errors [$($existing.errors)]"
}

function Invoke-LongPathScenario {
  param([int]$Length)
  $value = Get-LongPath $Length
  Invoke-Scenario "Path of $Length characters" $value 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-That 'the install puts cli\sesame.exe in place' $installed.terminalProgramExists $terminalProgram 'no file'
    Confirm-TerminalAdded 'the install' $before.machinePath $installed.machinePath
    Confirm-RecordAdded 'the install' $installed
    Confirm-Status 'the install' $installed $statusChanged
    Confirm-LookupFromNewCommandShell 'the install'
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the uninstall' $after
  }
}

function Invoke-ExistingEntryScenario {
  param([string]$Description, [string]$Entry)
  Invoke-Scenario "Path already holds the entry $Description" "$basePath;$Entry" 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-PathUnchanged 'an install over an entry Sesame did not add' $before.machinePath $installed.machinePath
    Confirm-NoRecord 'an install over an entry Sesame did not add' $installed
    Confirm-Status 'an install over an entry Sesame did not add' $installed $statusUnchanged
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'an uninstall that must keep an entry Sesame did not add' $before.machinePath $after.machinePath
    Confirm-That 'the entry Sesame did not add is still there' ((Get-PathEntries $after.machinePath.Value) -ccontains $Entry) $Entry (Format-PathValue $after.machinePath)
  }
}

function Invoke-CommandShellProbe {
  param([int]$Length, [string]$Early, [string]$Late, [string]$Session)
  $head = "$Early;$env:SystemRoot\system32;C:\Fictional\Pad\"
  $tail = ";$Late"
  $value = $head + ('x' * ($Length - $head.Length - $tail.Length)) + $tail
  try {
    $run = Invoke-Captured $commandShell "/d /c `"$Session`"" 60 $value
  } catch {
    $run = [pscustomobject][ordered]@{ command = "$commandShell $Session"; finished = $false; exitCode = $null; seconds = 0; output = ''; errors = "could not start: $($_.Exception.Message)" }
  }
  $child = [regex]::Match($run.output, 'child Path length (\d+)')
  $probe = [pscustomobject][ordered]@{
    length = $value.Length
    earlyFound = $run.output.Contains('fictional early probe ran')
    lateFound = $run.output.Contains('fictional late probe ran')
    pathDefined = $run.output.Contains('cmd sees PATH')
    childPathLength = if ($child.Success) { [int]$child.Groups[1].Value } else { -1 }
    errors = $run.errors.Trim()
  }
  Write-Host ("cmd probe: Path of {0} characters, first entry found {1}, last entry found {2}, PATH defined in cmd {3}, Path length in a child of cmd {4}, errors [{5}]" -f $probe.length, $probe.earlyFound, $probe.lateFound, $probe.pathDefined, $probe.childPathLength, $probe.errors)
  Save-Evidence "cmd probe $Length" ([ordered]@{ probe = $probe; run = $run })
  return $probe
}

function Invoke-CommandShellLimitScenario {
  Invoke-Scenario "A new cmd.exe given a Path around $commandShellLineLimit characters" $basePath 'ExpandString' {
    $probeRoot = Join-Path $EvidenceRoot 'cmd-path-probe'
    $early = Join-Path $probeRoot 'first'
    $late = Join-Path $probeRoot 'last'
    New-Item -ItemType Directory -Force -Path $early, $late | Out-Null
    Set-Content -LiteralPath (Join-Path $early 'fictional-early-probe.cmd') -Encoding ASCII -Value '@echo fictional early probe ran'
    Set-Content -LiteralPath (Join-Path $late 'fictional-late-probe.cmd') -Encoding ASCII -Value '@echo fictional late probe ran'
    $session = Join-Path $probeRoot 'session.cmd'
    Set-Content -LiteralPath $session -Encoding ASCII -Value @(
      '@echo off',
      'call fictional-early-probe',
      'call fictional-late-probe',
      'if defined PATH (echo cmd sees PATH) else (echo cmd sees no PATH)',
      '"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "$p = [Environment]::GetEnvironmentVariable(''Path''); if ($null -eq $p) { ''child Path missing'' } else { ''child Path length '' + $p.Length }"'
    )
    $probes = @(foreach ($length in @(8000, 8190, $commandShellLineLimit, ($commandShellLineLimit + 1), ($commandShellLineLimit + 2), 8300, 16384, 32000, ($environmentLimit - 1), $environmentLimit, ($environmentLimit + 1), 40000)) {
        Invoke-CommandShellProbe $length $early $late $session
      })
    Save-Evidence 'cmd probes' $probes
    foreach ($probe in $probes) {
      $found = "first {0}, last {1}, defined {2}, child length {3}" -f $probe.earlyFound, $probe.lateFound, $probe.pathDefined, $probe.childPathLength
      if ($probe.length -le $commandShellLineLimit) {
        $works = $probe.earlyFound -and $probe.lateFound -and $probe.pathDefined -and ($probe.childPathLength -eq $probe.length)
        Confirm-That "a new cmd.exe with a Path of $($probe.length) characters finds commands in its first and last entries and passes Path on whole" $works 'both probes found and the full length passed on' $found
      } else {
        $blind = (-not $probe.earlyFound) -and (-not $probe.lateFound) -and $probe.pathDefined
        Confirm-That "a new cmd.exe with a Path of $($probe.length) characters keeps PATH but finds no command through it, not even in the first entry" $blind 'neither probe found and PATH still defined' $found
        if ($probe.length -le 16384) {
          Confirm-That "a new cmd.exe with a Path of $($probe.length) characters still passes Path on whole" ($probe.childPathLength -eq $probe.length) "$($probe.length)" "$($probe.childPathLength)"
        }
      }
    }
  }
}

function Get-NsisStringLimit {
  $toolRoot = Join-Path $env:LOCALAPPDATA 'tauri\NSIS'
  foreach ($candidate in @((Join-Path $toolRoot 'makensis.exe'), (Join-Path $toolRoot 'Bin\makensis.exe'))) {
    if (-not (Test-Path -LiteralPath $candidate)) { continue }
    $info = Invoke-Captured $candidate '-HDRINFO' 60
    $match = [regex]::Match("$($info.output)`n$($info.errors)", 'NSIS_MAX_STRLEN=(\d+)')
    if ($match.Success) {
      return [pscustomobject][ordered]@{ limit = [int]$match.Groups[1].Value; makensis = $candidate; header = $info.output }
    }
  }
  return $null
}

Write-Host "runner machine Path at the start: $(Format-PathValue $originalPath)"
Write-Host "runner user Path at the start: $(Format-PathValue $originalUserPath)"
if (Get-UninstallKey) { throw 'Sesame is already installed, so this test cannot start from a clean machine.' }
if (Get-PathRecord) { throw 'A record of a Sesame Path entry already exists, so this test cannot start from a clean machine.' }
if (Test-Path -LiteralPath $installDirectory) { throw "$installDirectory already exists, so this test cannot start from a clean machine." }

try {
  $originalHolds = @((Get-PathEntries $originalPath.Value) | Where-Object { Test-TerminalEntry $_ }).Count
  Confirm-That 'the runner Path holds no Sesame entry before the test' ($originalHolds -eq 0) '0 entries' "$originalHolds entries"

  $nsis = Get-NsisStringLimit
  if ($nsis) {
    $limit = $nsis.limit
    Write-Host "NSIS_MAX_STRLEN of the makensis that built this installer, $($nsis.makensis): $limit"
  } else {
    $limit = 1024
    Write-Host "makensis -HDRINFO could not be read under $env:LOCALAPPDATA\tauri\NSIS, so the long Path cases are only placed around the standard limit of 1024"
  }
  Save-Evidence 'nsis string limit' ([ordered]@{ found = $nsis; limitUsed = $limit })

  Invoke-Scenario 'Silent install, the tool from a new session, the running desktop, reinstall, update and silent uninstall' $basePath 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Save-LifecycleEvidence 'command-line-installed'
    Confirm-InstalledPrograms
    Confirm-TerminalAdded 'the silent install' $before.machinePath $installed.machinePath
    Confirm-RecordAdded 'the silent install' $installed
    Confirm-Status 'the silent install' $installed $statusChanged
    Confirm-PathModeRefusals $installed.machinePath
    Confirm-Unexpanded 'the silent install' $installed
    $version = (Get-ItemProperty -LiteralPath $installed.uninstallKey).DisplayVersion
    $sessionPath = Confirm-ToolFromNewSession $version
    Confirm-ToolReachesDesktop $sessionPath
    Save-LifecycleEvidence 'command-line-after-desktop'

    Install-Sesame @('/S')
    $state = Get-State 'after silent reinstall'
    Confirm-PathUnchanged 'a silent reinstall' $installed.machinePath $state.machinePath
    Confirm-RecordAdded 'a silent reinstall' $state
    Confirm-Status 'a silent reinstall' $state $statusUnchanged

    Install-Sesame @('/P')
    $state = Get-State 'after passive reinstall'
    Confirm-PathUnchanged 'a passive reinstall' $installed.machinePath $state.machinePath
    Confirm-RecordAdded 'a passive reinstall' $state

    Install-Sesame @('/S', '/UPDATE')
    $state = Get-State 'after update'
    Confirm-PathUnchanged 'an update' $installed.machinePath $state.machinePath
    Confirm-RecordAdded 'an update' $state

    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Save-LifecycleEvidence 'command-line-uninstalled'
    Confirm-PathUnchanged 'the silent uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the silent uninstall' $after
    Confirm-Unexpanded 'the silent uninstall' $after
  }

  Invoke-Scenario 'Passive install and passive uninstall' $basePath 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/P')
    $installed = Get-State 'after install'
    Confirm-TerminalAdded 'the passive install' $before.machinePath $installed.machinePath
    Confirm-RecordAdded 'the passive install' $installed
    Uninstall-Sesame @('/P')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the passive uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the passive uninstall' $after
  }

  Invoke-ExistingEntryScenario 'in the same form' $terminalFolder
  Invoke-ExistingEntryScenario 'with a trailing backslash' "$terminalFolder\"
  Invoke-ExistingEntryScenario 'in different letter case' $terminalFolder.ToUpperInvariant()
  Invoke-ExistingEntryScenario 'in quotes' "`"$terminalFolder`""
  Invoke-ExistingEntryScenario 'written with %ProgramFiles%' '%ProgramFiles%\Sesame\cli'

  Invoke-Scenario 'A Path edit that fails leaves the install working' $basePath 'ExpandString' {
    Set-MachinePath ($basePath.Replace(';', "`n")) 'MultiString'
    $before = Get-State 'before install with a Path of type REG_MULTI_SZ'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-That 'the install still puts cli\sesame.exe in place' $installed.terminalProgramExists $terminalProgram 'no file'
    Confirm-PathUnchanged 'an install whose Path edit fails' $before.machinePath $installed.machinePath
    Confirm-NoRecord 'an install whose Path edit fails' $installed
    Confirm-Status 'an install whose Path edit fails' $installed $statusFailed
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall after a failed Path edit' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the uninstall after a failed Path edit' $after
  }

  Invoke-Scenario 'A silent uninstall whose Path edit fails finishes and keeps the record' $basePath 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-RecordAdded 'the install' $installed
    Register-BrowserHost
    Set-MachinePath ($installed.machinePath.Value.Replace(';', "`n")) 'MultiString'
    $broken = Get-State 'after the Path is changed to REG_MULTI_SZ'
    Uninstall-Sesame @('/S')
    $finished = Get-State 'after a silent uninstall that could not edit Path'
    Confirm-PathUnchanged 'a silent uninstall whose Path edit fails' $broken.machinePath $finished.machinePath
    Confirm-That 'a silent uninstall whose Path edit fails removes cli\sesame.exe' (-not $finished.terminalProgramExists) 'no file' $terminalProgram
    Confirm-That 'a silent uninstall whose Path edit fails removes the uninstall key' ($null -eq $finished.uninstallKey) 'no key' "$($finished.uninstallKey)"
    Confirm-RecordAdded 'a silent uninstall whose Path edit fails' $finished
    Confirm-That 'a silent uninstall whose Path edit fails still removes the browser registration' (-not (Test-Path -LiteralPath $chromeHostKey)) 'no Chrome registration' 'a Chrome registration'
    Set-MachinePath $installed.machinePath.Value $installed.machinePath.Kind
    Install-Sesame @('/S')
    $again = Get-State 'after the next install'
    Confirm-PathUnchanged 'the next install' $installed.machinePath $again.machinePath
    Confirm-RecordAdded 'the next install' $again
    Confirm-Status 'the next install' $again $statusUnchanged
    Uninstall-Sesame @('/S')
    $after = Get-State 'after the next uninstall'
    Confirm-PathUnchanged 'the next uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the next uninstall' $after
  }

  Invoke-Scenario 'A deployment that runs uninstall.exe /S and waits when the Path edit fails' $basePath 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-RecordAdded 'the install' $installed
    Set-MachinePath ($installed.machinePath.Value.Replace(';', "`n")) 'MultiString'
    $broken = Get-State 'after the Path is changed to REG_MULTI_SZ'
    $command = (Get-ItemProperty -LiteralPath $installed.uninstallKey).UninstallString
    Confirm-That 'the registered uninstall command is the installed uninstaller' ($command -ieq "`"$uninstaller`"") "`"$uninstaller`"" "$command"
    $code = Invoke-Installer $uninstaller @('/S')
    $waited = Wait-UninstallCopy
    $ended = Get-State 'after a deployment uninstall that could not edit Path'
    Write-Host ("deployment uninstall: uninstall.exe /S exited {0}, its temporary copy ran {1} more seconds, uninstall key left {2}, cli\sesame.exe left {3}, record left {4}" -f $code, $waited, ($null -ne $ended.uninstallKey), $ended.terminalProgramExists, ($null -ne $ended.terminalPathRecord))
    Save-Evidence 'deployment uninstall outcome' ([ordered]@{ exitCode = $code; copySeconds = $waited; state = $ended })
    Confirm-That 'a deployment uninstall whose Path edit fails exits 0' ($code -eq 0) '0' "$code"
    Confirm-PathUnchanged 'a deployment uninstall whose Path edit fails' $broken.machinePath $ended.machinePath
    Confirm-That 'a deployment uninstall whose Path edit fails removes Sesame as it reported' (($null -eq $ended.uninstallKey) -and (-not $ended.terminalProgramExists)) 'no uninstall key and no cli\sesame.exe' "key $($ended.uninstallKey), cli\sesame.exe present $($ended.terminalProgramExists)"
    Confirm-RecordAdded 'a deployment uninstall whose Path edit fails' $ended
    Set-MachinePath $installed.machinePath.Value $installed.machinePath.Kind
    Install-Sesame @('/S')
    Uninstall-Sesame @('/S')
    $after = Get-State 'after the next install and uninstall'
    Confirm-PathUnchanged 'the next install and uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the next install and uninstall' $after
  }

  Invoke-Scenario 'An uninstall after someone else removed the entry' $basePath 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-RecordAdded 'the install' $installed
    Set-MachinePath $before.machinePath.Value $before.machinePath.Kind
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'an uninstall that finds the entry gone' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'an uninstall that finds the entry gone' $after
  }

  Invoke-Scenario 'Path holds the entry twice at uninstall' $basePath 'ExpandString' {
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-RecordAdded 'the install' $installed
    Set-MachinePath "$($installed.machinePath.Value);$terminalFolder" $installed.machinePath.Kind
    $doubled = Get-State 'after a second copy of the entry is added'
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'an uninstall that finds the entry twice' $doubled.machinePath $after.machinePath
  }

  Invoke-Scenario 'Path of type REG_SZ' $basePath 'String' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-TerminalAdded 'the install over REG_SZ' $before.machinePath $installed.machinePath
    Confirm-RecordAdded 'the install over REG_SZ' $installed
    Confirm-Unexpanded 'the install over REG_SZ' $installed
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall from REG_SZ' $before.machinePath $after.machinePath
  }

  Invoke-Scenario 'Path that ends with a semicolon' "$basePath;" 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-TerminalAdded 'the install' $before.machinePath $installed.machinePath
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall' $before.machinePath $after.machinePath
  }

  Invoke-Scenario 'Update-mode uninstall keeps the entry' $basePath 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-TerminalAdded 'the install' $before.machinePath $installed.machinePath
    Uninstall-Sesame @('/S', '/UPDATE')
    $updating = Get-State 'after update-mode uninstall'
    Confirm-PathUnchanged 'an update-mode uninstall' $installed.machinePath $updating.machinePath
    Confirm-RecordAdded 'an update-mode uninstall' $updating
    Install-Sesame @('/S', '/UPDATE')
    $updated = Get-State 'after update install'
    Confirm-PathUnchanged 'the update install' $installed.machinePath $updated.machinePath
    Confirm-RecordAdded 'the update install' $updated
    Confirm-That 'the update install puts cli\sesame.exe back' $updated.terminalProgramExists $terminalProgram 'no file'
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the final uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the final uninstall' $after
  }

  foreach ($length in @(994, 995, 1022, 1023, 1024, 4096)) {
    Invoke-LongPathScenario $length
  }

  $room = $commandShellLineLimit - $terminalFolder.Length - 1
  Invoke-Scenario "Path that reaches $commandShellLineLimit characters with the entry" (Get-LongPathExpandedTo $room) 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-TerminalAdded 'the install' $before.machinePath $installed.machinePath
    Confirm-RecordAdded 'the install' $installed
    Confirm-Status 'the install' $installed $statusChanged
    $session = Get-MachineSessionPath $installed
    Confirm-That "the install leaves the expanded Path at $commandShellLineLimit characters" ($session.Length -eq $commandShellLineLimit) "$commandShellLineLimit" "$($session.Length)"
    Confirm-LookupFromNewCommandShell 'the install' $session
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the uninstall' $after
  }

  Invoke-Scenario "Path one character too long to add the entry without passing $commandShellLineLimit characters" (Get-LongPathExpandedTo ($room + 1)) 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-That 'the install still puts cli\sesame.exe in place' $installed.terminalProgramExists $terminalProgram 'no file'
    Confirm-PathUnchanged "an install that would pass $commandShellLineLimit characters" $before.machinePath $installed.machinePath
    Confirm-NoRecord "an install that would pass $commandShellLineLimit characters" $installed
    Confirm-Status "an install that would pass $commandShellLineLimit characters" $installed "$statusRefused"
    Confirm-LookupFromNewCommandShell 'a refused install' (Get-MachineSessionPath $installed) -WithoutTool
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the uninstall' $after
  }

  Invoke-Scenario "Path already past $commandShellLineLimit characters" (Get-LongPathExpandedTo ($commandShellLineLimit + 1)) 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-TerminalAdded 'the install' $before.machinePath $installed.machinePath
    Confirm-RecordAdded 'the install' $installed
    Confirm-Status 'the install' $installed $statusChanged
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the uninstall' $after
  }

  $longest = $environmentLimit - $terminalFolder.Length - 1
  Invoke-Scenario "Path of $longest characters, the longest that leaves room for the entry" (Get-LongPath $longest) 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-TerminalAdded 'the install' $before.machinePath $installed.machinePath
    Confirm-That "the install leaves Path at $environmentLimit characters" ($installed.machinePath.Length -eq $environmentLimit) "$environmentLimit" "$($installed.machinePath.Length)"
    Confirm-RecordAdded 'the install' $installed
    Confirm-Status 'the install' $installed $statusChanged
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the uninstall' $after
  }

  Invoke-Scenario "Path of $($longest + 1) characters, too long to add the entry" (Get-LongPath ($longest + 1)) 'ExpandString' {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-That 'the install still puts cli\sesame.exe in place' $installed.terminalProgramExists $terminalProgram 'no file'
    Confirm-PathUnchanged "an install that would pass $environmentLimit characters" $before.machinePath $installed.machinePath
    Confirm-NoRecord "an install that would pass $environmentLimit characters" $installed
    Confirm-Status "an install that would pass $environmentLimit characters" $installed "$statusRefused"
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the uninstall' $after
  }

  Invoke-CommandShellLimitScenario

  Write-Host "The runner Path has $($originalPath.Length) characters and the installer must add the entry to it"
  Invoke-Scenario "The runner's own Path of $($originalPath.Length) characters" $originalPath.Value $originalPath.Kind {
    $before = Get-State 'before install'
    Install-Sesame @('/S')
    $installed = Get-State 'after install'
    Confirm-TerminalAdded 'the install' $before.machinePath $installed.machinePath
    Confirm-RecordAdded 'the install' $installed
    Confirm-Status 'the install' $installed $statusChanged
    Uninstall-Sesame @('/S')
    $after = Get-State 'after uninstall'
    Confirm-PathUnchanged 'the uninstall' $before.machinePath $after.machinePath
    Confirm-TerminalRemoved 'the uninstall' $after
  }
} finally {
  $script:scenario = 'final restore'
  try {
    Reset-Install
  } catch {
    Add-Failure "the final cleanup failed: $($_.Exception.Message)"
  }
  Set-MachinePath $originalPath.Value $originalPath.Kind
  $restored = Get-MachinePath
  Confirm-PathUnchanged 'restoring the runner Path' $originalPath $restored
  $userPath = Get-UserPath
  $userSame = ($userPath.Exists -eq $originalUserPath.Exists) -and ($userPath.Kind -eq $originalUserPath.Kind) -and [string]::Equals($userPath.Value, $originalUserPath.Value, [StringComparison]::Ordinal)
  Confirm-That 'the user Path is untouched' $userSame (Format-PathValue $originalUserPath) (Format-PathValue $userPath)
  Save-Evidence 'summary' ([ordered]@{ scenarios = $script:scenarioCount; failures = @($script:failures); restoredMachinePath = $restored; userPath = $userPath })
}

Write-Host ''
if ($script:failures.Count -gt 0) {
  Write-Host "$($script:failures.Count) checks failed in $script:scenarioCount scenarios:"
  foreach ($failure in $script:failures) { Write-Host "  $failure" }
  throw "$($script:failures.Count) command line install checks failed."
}
Write-Host "Command line install passed $script:scenarioCount scenarios"
