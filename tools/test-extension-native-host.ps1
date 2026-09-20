[CmdletBinding()]
param(
  [ValidateSet('Chrome', 'Chromium')]
  [string]$Browser = 'Chrome',
  [string]$ExtensionDirectory = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'sesame-browser-extension'),
  [switch]$ManualFill
)

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $workspace 'src-tauri\Cargo.toml'
$hostName = 'app.usesesame.browser'
$extensionId = 'idbkfhhjnniibleeanchljhakfhecnlg'
$extensionCheckout = (Resolve-Path -LiteralPath $ExtensionDirectory -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath (Join-Path $extensionCheckout 'package.json') -PathType Leaf)) {
  throw "The extension checkout at $extensionCheckout has no package.json."
}
if (-not (Test-Path -LiteralPath (Join-Path $extensionCheckout 'node_modules') -PathType Container)) {
  throw "The extension dependencies are missing. Run npm ci in $extensionCheckout first."
}
$programFilesX86 = ${env:ProgramFiles(x86)}
$browserConfig = @{
  Chrome = @{
    RegistryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"
    Channel = 'chrome'
    Executables = @(
      (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
      $(if ($programFilesX86) { Join-Path $programFilesX86 'Google\Chrome\Application\chrome.exe' }),
      (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe')
    )
  }
  Chromium = @{
    RegistryPath = "HKCU:\Software\Chromium\NativeMessagingHosts\$hostName"
    Channel = 'chromium'
    Executables = @(
      (Join-Path $env:LOCALAPPDATA 'Chromium\Application\chrome.exe'),
      (Join-Path $env:ProgramFiles 'Chromium\Application\chrome.exe')
    )
  }
}[$Browser]
$registryPath = $browserConfig.RegistryPath

function Resolve-BrowserExecutable {
  param(
    [string]$Name,
    [string[]]$Candidates
  )
  if ($env:SESAME_BROWSER_TEST_EXECUTABLE) {
    if (Test-Path -LiteralPath $env:SESAME_BROWSER_TEST_EXECUTABLE -PathType Leaf) {
      return (Resolve-Path -LiteralPath $env:SESAME_BROWSER_TEST_EXECUTABLE).Path
    }
    throw "SESAME_BROWSER_TEST_EXECUTABLE points at a missing file: $env:SESAME_BROWSER_TEST_EXECUTABLE"
  }
  foreach ($candidate in $Candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }
  if ($env:LOCALAPPDATA) {
    $playwrightDirectory = Join-Path $env:LOCALAPPDATA 'ms-playwright'
    if (Test-Path -LiteralPath $playwrightDirectory -PathType Container) {
      $bundled = Get-ChildItem -LiteralPath $playwrightDirectory -Recurse -Filter 'chrome.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($bundled) { return $bundled.FullName }
    }
  }
  throw "No $Name browser executable found. Install it or set SESAME_BROWSER_TEST_EXECUTABLE."
}

$previousTauriConfig = $env:TAURI_CONFIG
try {
  $env:TAURI_CONFIG = '{"bundle":{"externalBin":[]}}'
  & cargo build --manifest-path $manifest --release --features browser-helper-dev --bin sesame-browser-host
  if ($LASTEXITCODE -ne 0) { throw 'The native host build failed.' }
} finally {
  if ($null -eq $previousTauriConfig) {
    Remove-Item Env:\TAURI_CONFIG -ErrorAction SilentlyContinue
  } else {
    $env:TAURI_CONFIG = $previousTauriConfig
  }
}

$metadata = (& cargo metadata --manifest-path $manifest --no-deps --format-version 1 | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata could not be read.' }
$hostPath = Join-Path $metadata.target_directory 'release\sesame-browser-host.exe'
if (-not (Test-Path -LiteralPath $hostPath -PathType Leaf)) {
  throw "The native host executable was not found at $hostPath."
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testDirectory = Join-Path $tempBase "sesame-native-host-test-$([Guid]::NewGuid().ToString('N'))"
$resolvedTestDirectory = [IO.Path]::GetFullPath($testDirectory)
if (-not $resolvedTestDirectory.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'The native-host test directory escaped the system temporary directory.'
}

$existingKey = Get-Item -LiteralPath $registryPath -ErrorAction SilentlyContinue
$hadExistingKey = $null -ne $existingKey
$previousDefault = if ($hadExistingKey) { $existingKey.GetValue('') } else { $null }
$previousBrowserExecutable = $env:SESAME_BROWSER_TEST_EXECUTABLE

try {
  New-Item -ItemType Directory -Path $resolvedTestDirectory -Force | Out-Null
  $hostManifestPath = Join-Path $resolvedTestDirectory "$hostName.json"
  $hostManifest = [ordered]@{
    name = $hostName
    description = 'Sesame disposable native-host integration test'
    path = $hostPath
    type = 'stdio'
    allowed_origins = @("chrome-extension://$extensionId/")
  }
  [IO.File]::WriteAllText(
    $hostManifestPath,
    ($hostManifest | ConvertTo-Json -Depth 3),
    [Text.UTF8Encoding]::new($false)
  )

  New-Item -Force -Path $registryPath | Out-Null
  Set-Item -LiteralPath $registryPath -Value $hostManifestPath

  $env:SESAME_BROWSER_TEST_EXECUTABLE = Resolve-BrowserExecutable -Name $Browser -Candidates $browserConfig.Executables
  $env:SESAME_NATIVE_HOST_TEST = '1'
  $env:SESAME_NATIVE_HOST_BROWSER = $browserConfig.Channel
  if ($ManualFill) {
    $env:SESAME_MANUAL_NATIVE_FILL = '1'
    Write-Host 'Sesame must be running and unlocked. This run saves a disposable login and then fills it, so approve both prompts in Sesame.'
    & npm.cmd --prefix $extensionCheckout run test:browser -- --testNamePattern 'disposable login'
  } else {
    & npm.cmd --prefix $extensionCheckout run test:browser -- --testNamePattern 'registered Windows native host'
  }
  if ($LASTEXITCODE -ne 0) { throw 'The native-host browser integration test failed.' }
} finally {
  Remove-Item Env:\SESAME_NATIVE_HOST_TEST -ErrorAction SilentlyContinue
  Remove-Item Env:\SESAME_NATIVE_HOST_BROWSER -ErrorAction SilentlyContinue
  Remove-Item Env:\SESAME_MANUAL_NATIVE_FILL -ErrorAction SilentlyContinue
  if ($null -ne $previousBrowserExecutable) {
    $env:SESAME_BROWSER_TEST_EXECUTABLE = $previousBrowserExecutable
  } else {
    Remove-Item Env:\SESAME_BROWSER_TEST_EXECUTABLE -ErrorAction SilentlyContinue
  }
  if ($hadExistingKey) {
    Set-Item -LiteralPath $registryPath -Value $previousDefault
  } else {
    Remove-Item -LiteralPath $registryPath -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path -LiteralPath $resolvedTestDirectory) {
    Remove-Item -LiteralPath $resolvedTestDirectory -Recurse -Force
  }
  if (Test-Path -LiteralPath $resolvedTestDirectory) {
    throw 'The native-host test left its temporary manifest behind.'
  }
  if ($hadExistingKey) {
    if ((Get-Item -LiteralPath $registryPath).GetValue('') -ne $previousDefault) {
      throw 'The native-host test did not restore the existing browser registration.'
    }
  } elseif (Test-Path -LiteralPath $registryPath) {
    throw 'The native-host test left a browser registration behind.'
  }
}
