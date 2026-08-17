[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $workspace 'src-tauri\Cargo.toml'

$previousTauriConfig = $env:TAURI_CONFIG
$previousRustFlags = $env:RUSTFLAGS
try {
  # Bootstrap the declared sidecar without asking Tauri to validate a binary that has not been staged yet.
  $env:TAURI_CONFIG = '{"bundle":{"externalBin":[]}}'
  # Link the MSVC runtime statically; Chromium launches the host directly, and a clean VM has no VCRUNTIME140.dll.
  $env:RUSTFLAGS = if ([string]::IsNullOrWhiteSpace($previousRustFlags)) {
    '-C target-feature=+crt-static'
  } else {
    "$previousRustFlags -C target-feature=+crt-static"
  }
  & cargo build --manifest-path $manifest --release --features browser-helper-dev --bin sesame-browser-host
  if ($LASTEXITCODE -ne 0) { throw 'The Sesame browser host build failed.' }
} finally {
  if ($null -eq $previousTauriConfig) {
    Remove-Item Env:\TAURI_CONFIG -ErrorAction SilentlyContinue
  } else {
    $env:TAURI_CONFIG = $previousTauriConfig
  }
  if ($null -eq $previousRustFlags) {
    Remove-Item Env:\RUSTFLAGS -ErrorAction SilentlyContinue
  } else {
    $env:RUSTFLAGS = $previousRustFlags
  }
}

$hostLine = (& rustc -vV | Where-Object { $_ -like 'host:*' } | Select-Object -First 1)
if (-not $hostLine) { throw 'Rust did not report a target triple.' }
$targetTriple = $hostLine.Substring(5).Trim()

$metadata = (& cargo metadata --manifest-path $manifest --no-deps --format-version 1 | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata could not be read.' }
$extension = if ($IsWindows -or $env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$source = Join-Path $metadata.target_directory "release\sesame-browser-host$extension"
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
  throw "The built Sesame browser host was not found at $source."
}

$stageDirectory = Join-Path $workspace 'src-tauri\binaries'
New-Item -ItemType Directory -Force -Path $stageDirectory | Out-Null
$destination = Join-Path $stageDirectory "sesame-browser-host-$targetTriple$extension"
Copy-Item -LiteralPath $source -Destination $destination -Force
Write-Host "Staged the Sesame browser host sidecar for $targetTriple."
