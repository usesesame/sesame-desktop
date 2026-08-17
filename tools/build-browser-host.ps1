[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $workspace 'src-tauri\Cargo.toml'
$previousTauriConfig = $env:TAURI_CONFIG

try {
  # The bundle declares this executable as a sidecar; disable sidecar validation only while bootstrapping it.
  $env:TAURI_CONFIG = '{"bundle":{"externalBin":[]}}'
  & cargo build --manifest-path $manifest --features browser-helper-dev --bin sesame-browser-host
  if ($LASTEXITCODE -ne 0) { throw 'The Sesame browser host build failed.' }
} finally {
  if ($null -eq $previousTauriConfig) {
    Remove-Item Env:\TAURI_CONFIG -ErrorAction SilentlyContinue
  } else {
    $env:TAURI_CONFIG = $previousTauriConfig
  }
}
