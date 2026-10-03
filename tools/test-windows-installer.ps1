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
  if (-not $process.WaitForExit(300000)) {
    $process.Kill()
    throw "$Path $Arguments did not finish within 5 minutes."
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

function Set-OldRecord {
  param([string]$Directory)
  if (Test-Path -LiteralPath (Join-Path $expectedDirectory 'uninstall.exe')) {
    $code = Invoke-Installer (Join-Path $expectedDirectory 'uninstall.exe') @('/S', "_?=$expectedDirectory")
    Assert-True ($code -eq 0) "the current install uninstalls before the next case, got $code"
  }
  Remove-Item -LiteralPath $expectedDirectory -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -Path $uninstallKey -Force | Out-Null
  Set-ItemProperty -LiteralPath $uninstallKey -Name 'DisplayVersion' -Value $version
  Set-ItemProperty -LiteralPath $uninstallKey -Name 'UninstallString' -Value "`"$Directory\uninstall.exe`""
  New-Item -Path $locationKey -Force | Out-Null
  Set-ItemProperty -LiteralPath $locationKey -Name '(default)' -Value $Directory
}

Set-OldRecord $untrustedDirectory
$code = Invoke-Installer $installer @('/P')
Assert-True ($code -eq 0) "the passive reinstall exits 0, got $code"
Assert-True (-not (Test-Path -LiteralPath $decoyMarker)) 'the old uninstaller outside Program Files never runs'
$kept = @($mainBinary, 'uninstall.exe', 'keep.txt') | Where-Object { Test-Path -LiteralPath (Join-Path $untrustedDirectory $_) }
Assert-True ($kept.Count -eq 3) 'nothing is removed from the old directory outside Program Files'
Assert-True (Test-Path -LiteralPath (Join-Path $expectedDirectory $mainBinary)) "$mainBinary is installed in Program Files"
Assert-True ((Get-ItemProperty -LiteralPath $uninstallKey).InstallLocation.Trim('"') -eq $expectedDirectory) 'the uninstall key points at Program Files'

Write-Host 'Reinstall over an old install inside Program Files'
$trustedOldDirectory = Join-Path $env:ProgramFiles 'SesameOldInstall'
New-Item -ItemType Directory -Path $trustedOldDirectory -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $untrustedDirectory 'uninstall.exe') -Destination (Join-Path $trustedOldDirectory 'uninstall.exe')
Set-OldRecord $trustedOldDirectory
$code = Invoke-Installer $installer @('/P')
Assert-True ($code -eq 0) "the passive reinstall over a Program Files install exits 0, got $code"
Assert-True (Test-Path -LiteralPath $decoyMarker) 'the old uninstaller inside Program Files runs'
Assert-True (-not (Test-Path -LiteralPath $trustedOldDirectory)) 'the old Program Files directory is removed after its uninstaller succeeds'
Assert-True (Test-Path -LiteralPath (Join-Path $expectedDirectory $mainBinary)) "$mainBinary is installed in Program Files"
Remove-Item -LiteralPath $decoyMarker -Force

Write-Host 'Reinstall over a recorded traversal path'
Set-OldRecord (Join-Path $env:ProgramFiles "..\$(Split-Path -Leaf $untrustedDirectory)")
$code = Invoke-Installer $installer @('/P')
Assert-True ($code -eq 0) "the passive reinstall over a traversal path exits 0, got $code"
Assert-True (-not (Test-Path -LiteralPath $decoyMarker)) 'a traversal path into Program Files does not run the old uninstaller'
Assert-True (Test-Path -LiteralPath (Join-Path $untrustedDirectory 'uninstall.exe')) 'the old uninstaller behind the traversal path is left in place'
Assert-True (Test-Path -LiteralPath (Join-Path $expectedDirectory $mainBinary)) "$mainBinary is installed in Program Files"

$code = Invoke-Installer (Join-Path $expectedDirectory 'uninstall.exe') @('/S', "_?=$expectedDirectory")
Assert-True ($code -eq 0) "the final uninstall exits 0, got $code"
Remove-Item -LiteralPath $expectedDirectory, $untrustedDirectory, $trustedOldDirectory -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Installer lifecycle passed'
