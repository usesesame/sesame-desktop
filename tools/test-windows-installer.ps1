[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$InstallerPath
)

$ErrorActionPreference = 'Stop'

$productName = 'Sesame'
$expectedDirectory = Join-Path $env:ProgramFiles $productName
$untrustedDirectory = Join-Path $env:SystemDrive 'SesameUntrustedOldInstall'
$decoyMarker = Join-Path $env:RUNNER_TEMP 'sesame-old-uninstaller-ran.txt'
$uninstallKeys = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$productName",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$productName"
)

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
  Write-Host "ok: $Message"
}

function Invoke-Installer {
  param([string]$Path, [string[]]$Arguments)
  $process = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru
  $null = $process.Handle
  if (-not $process.WaitForExit(600000)) {
    $process.Kill()
    throw "$Path $Arguments did not finish within 10 minutes."
  }
  return $process.ExitCode
}

function Get-UninstallKey {
  foreach ($key in $uninstallKeys) {
    if (Test-Path -LiteralPath $key) { return $key }
  }
  return $null
}

function Get-InstallLocationKey {
  foreach ($root in 'HKLM:\SOFTWARE\WOW6432Node', 'HKLM:\SOFTWARE') {
    foreach ($vendor in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
      $candidate = Join-Path $vendor.PSPath $productName
      if (-not (Test-Path -LiteralPath $candidate)) { continue }
      $location = (Get-Item -LiteralPath $candidate).GetValue('')
      if ($location -eq $expectedDirectory) { return $candidate }
    }
  }
  return $null
}

$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
Remove-Item -LiteralPath $decoyMarker -Force -ErrorAction SilentlyContinue

Write-Host 'Fresh silent install'
$code = Invoke-Installer $installer @('/S')
Assert-True ($code -eq 0) "the silent install exits 0, got $code"
$uninstallKey = Get-UninstallKey
Assert-True ($null -ne $uninstallKey) 'the install writes its uninstall key'
$uninstall = Get-ItemProperty -LiteralPath $uninstallKey
$mainBinary = $uninstall.MainBinaryName
$version = $uninstall.DisplayVersion
Assert-True ($uninstall.InstallLocation.Trim('"') -eq $expectedDirectory) "the install location is $expectedDirectory"
Assert-True (Test-Path -LiteralPath (Join-Path $expectedDirectory $mainBinary)) "$mainBinary is installed in Program Files"
Assert-True (Test-Path -LiteralPath (Join-Path $expectedDirectory 'uninstall.exe')) 'the uninstaller is installed in Program Files'
$locationKey = Get-InstallLocationKey
Assert-True ($null -ne $locationKey) 'the install records its location'

Write-Host 'Silent uninstall'
$code = Invoke-Installer (Join-Path $expectedDirectory 'uninstall.exe') @('/S', "_?=$expectedDirectory")
Assert-True ($code -eq 0) "the silent uninstall exits 0, got $code"
Assert-True (-not (Test-Path -LiteralPath (Join-Path $expectedDirectory $mainBinary))) "$mainBinary is removed"
Assert-True ($null -eq (Get-UninstallKey)) 'the uninstall key is removed'
Remove-Item -LiteralPath $expectedDirectory -Recurse -Force -ErrorAction SilentlyContinue

Write-Host 'Reinstall over an old record outside Program Files'
New-Item -ItemType Directory -Path $untrustedDirectory -Force | Out-Null
$escapedMarker = $decoyMarker.Replace('\', '\\')
$decoySource = @"
public static class Decoy {
  public static int Main(string[] args) {
    System.IO.File.WriteAllText("$escapedMarker", string.Join(" ", args));
    return 0;
  }
}
"@
Add-Type -TypeDefinition $decoySource -OutputAssembly (Join-Path $untrustedDirectory 'uninstall.exe') -OutputType ConsoleApplication
Set-Content -LiteralPath (Join-Path $untrustedDirectory $mainBinary) -Value 'fictional old binary'
Set-Content -LiteralPath (Join-Path $untrustedDirectory 'keep.txt') -Value 'fictional user file'
New-Item -Path $uninstallKey -Force | Out-Null
Set-ItemProperty -LiteralPath $uninstallKey -Name 'DisplayVersion' -Value $version
Set-ItemProperty -LiteralPath $uninstallKey -Name 'UninstallString' -Value "`"$untrustedDirectory\uninstall.exe`""
New-Item -Path $locationKey -Force | Out-Null
Set-ItemProperty -LiteralPath $locationKey -Name '(default)' -Value $untrustedDirectory

$code = Invoke-Installer $installer @('/P')
Assert-True ($code -eq 0) "the passive reinstall exits 0, got $code"
Assert-True (-not (Test-Path -LiteralPath $decoyMarker)) 'the old uninstaller outside Program Files never runs'
Assert-True (-not (Test-Path -LiteralPath (Join-Path $untrustedDirectory $mainBinary))) "the old $mainBinary is removed"
Assert-True (-not (Test-Path -LiteralPath (Join-Path $untrustedDirectory 'uninstall.exe'))) 'the old uninstaller is removed'
Assert-True (Test-Path -LiteralPath (Join-Path $untrustedDirectory 'keep.txt')) 'a file the installer did not place is kept'
Assert-True (Test-Path -LiteralPath (Join-Path $expectedDirectory $mainBinary)) "$mainBinary is installed in Program Files"
Assert-True ((Get-ItemProperty -LiteralPath $uninstallKey).InstallLocation.Trim('"') -eq $expectedDirectory) 'the uninstall key points at Program Files'

$code = Invoke-Installer (Join-Path $expectedDirectory 'uninstall.exe') @('/S', "_?=$expectedDirectory")
Assert-True ($code -eq 0) "the final uninstall exits 0, got $code"
Remove-Item -LiteralPath $expectedDirectory, $untrustedDirectory -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Installer lifecycle passed'
