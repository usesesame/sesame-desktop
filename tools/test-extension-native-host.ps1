[CmdletBinding()]
param(
  [ValidateSet('Chromium')]
  [string]$Browser = 'Chromium',
  [switch]$ManualFill
)

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $workspace 'src-tauri\Cargo.toml'
$extensionDirectory = Join-Path $workspace 'extensions\sesame'
$hostName = 'app.usesesame.browser'
$extensionId = 'idbkfhhjnniibleeanchljhakfhecnlg'
$browserConfig = @{
  Chromium = @{ RegistryPath = "HKCU:\Software\Chromium\NativeMessagingHosts\$hostName"; Channel = 'chromium' }
}[$Browser]
$registryPath = $browserConfig.RegistryPath

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

  $env:SESAME_NATIVE_HOST_TEST = '1'
  $env:SESAME_NATIVE_HOST_BROWSER = $browserConfig.Channel
  if ($ManualFill) {
    $env:SESAME_MANUAL_NATIVE_FILL = '1'
    Write-Host 'Approve the disposable localhost fill in the Sesame desktop app when prompted.'
    & npm.cmd --prefix $extensionDirectory run test:browser -- --grep 'disposable login'
  } else {
    & npm.cmd --prefix $extensionDirectory run test:browser -- --grep 'registered Windows native host'
  }
  if ($LASTEXITCODE -ne 0) { throw 'The native-host browser integration test failed.' }
} finally {
  Remove-Item Env:\SESAME_NATIVE_HOST_TEST -ErrorAction SilentlyContinue
  Remove-Item Env:\SESAME_NATIVE_HOST_BROWSER -ErrorAction SilentlyContinue
  Remove-Item Env:\SESAME_MANUAL_NATIVE_FILL -ErrorAction SilentlyContinue
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
