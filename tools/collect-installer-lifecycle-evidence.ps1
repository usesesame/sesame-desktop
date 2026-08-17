[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[A-Za-z0-9._-]+$')]
  [string]$Label,

  [string]$OutputRoot = (Join-Path $PSScriptRoot '..\release-evidence\installer-lifecycle'),

  [string]$InstallerPath
)

$ErrorActionPreference = 'Stop'

function Get-Sha256Hex {
  param([Parameter(Mandatory = $true)][string]$LiteralPath)

  # Hash with the runtime directly; the collector must also run in stripped-down VMs where Get-FileHash is unavailable.
  $stream = [System.IO.File]::OpenRead($LiteralPath)
  try {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
      return ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
      $sha256.Dispose()
    }
  } finally {
    $stream.Dispose()
  }
}

$dataRoot = Join-Path $env:LOCALAPPDATA 'app.usesesame.desktop'
$nativeManifest = Join-Path $dataRoot 'native-messaging\app.usesesame.browser.json'
$excludedDataRoots = @('EBWebView', 'logs')
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$output = Join-Path $OutputRoot "$stamp-$Label"
New-Item -ItemType Directory -Force -Path $output | Out-Null

$operatingSystem = $null
try {
  $operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
  # Locked-down VMs deny CIM; registry and runtime values still provide the Windows identity.
}
$windowsRegistry = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$system = [ordered]@{
  capturedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
  computerName = $env:COMPUTERNAME
  userName = $env:USERNAME
  isAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  windowsProductName = if ($operatingSystem) { $operatingSystem.Caption } else { $windowsRegistry.ProductName }
  windowsVersion = if ($operatingSystem) { $operatingSystem.Version } else { [Environment]::OSVersion.Version.ToString() }
  windowsBuildNumber = if ($operatingSystem) { $operatingSystem.BuildNumber } else { $windowsRegistry.CurrentBuildNumber }
  osArchitecture = if ($operatingSystem) { $operatingSystem.OSArchitecture } else { [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
}
$system | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $output 'system.json')

$webView = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\*', 'HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\*' -ErrorAction SilentlyContinue |
  Where-Object { $_.name -like '*WebView2*' } |
  Select-Object name, pv
$webView | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8 (Join-Path $output 'webview2.json')

if ($InstallerPath) {
  $resolvedInstaller = Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop
  [pscustomobject][ordered]@{
    Path = $resolvedInstaller.Path
    Algorithm = 'SHA256'
    Hash = (Get-Sha256Hex -LiteralPath $resolvedInstaller.Path).ToUpperInvariant()
  } | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $output 'installer-hash.json')
}

$files = @()
if (Test-Path -LiteralPath $dataRoot) {
  $dataRootPrefix = $dataRoot.TrimEnd('\') + '\'
  $files = @(Get-ChildItem -LiteralPath $dataRoot -Recurse -File -Force |
    Sort-Object FullName |
    ForEach-Object {
      $relativePath = $_.FullName.Substring($dataRootPrefix.Length)
      $topLevel = ($relativePath -split '\\', 2)[0]
      if ($excludedDataRoots -contains $topLevel) {
        return
      }
      [pscustomobject][ordered]@{
        relativePath = $relativePath
        length = $_.Length
        lastWriteTimeUtc = $_.LastWriteTimeUtc.ToString('o')
        sha256 = Get-Sha256Hex -LiteralPath $_.FullName
      }
    })
}
$collectorPolicy = [ordered]@{
  dataRoot = $dataRoot
  excludedTopLevelRoots = $excludedDataRoots
  reason = 'WebView cache/profile state and diagnostic logs are volatile runtime data, not lifecycle-preservation evidence. Every other file under the bundle-ID root must hash successfully.'
}
$collectorPolicy | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $output 'collector-policy.json')
$dataCsv = Join-Path $output 'data-files.csv'
if ($files.Count -eq 0) {
  '"relativePath","length","lastWriteTimeUtc","sha256"' | Set-Content -Encoding utf8 $dataCsv
} else {
  $files | Export-Csv -NoTypeInformation -Encoding utf8 -LiteralPath $dataCsv
}

$installed = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -like '*Sesame*' } |
  Select-Object DisplayName, DisplayVersion, InstallLocation, UninstallString
$installed | ConvertTo-Json -Depth 3 | Set-Content -Encoding utf8 (Join-Path $output 'installed-product.json')

$nativeHost = [ordered]@{
  chromeRegistered = Test-Path 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\app.usesesame.browser'
  edgeRegistered = Test-Path 'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\app.usesesame.browser'
  manifestExists = Test-Path -LiteralPath $nativeManifest
}
$nativeHost | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $output 'native-host-state.json')

Get-Process -Name 'sesame', 'sesame-browser-host' -ErrorAction SilentlyContinue |
  Select-Object ProcessName, Id, Path |
  Export-Csv -NoTypeInformation -Encoding utf8 (Join-Path $output 'processes.csv')

Write-Output $output
