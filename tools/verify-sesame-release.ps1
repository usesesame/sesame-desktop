param(
  [Parameter(Mandatory = $true)][string]$Installer,
  [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
  [switch]$HashOnly
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$manifests = @(Get-ChildItem -LiteralPath $root -Filter 'sesame-*-windows-*.release.json' -File)
if ($manifests.Count -ne 1) { throw 'The evidence directory must contain exactly one Sesame release manifest.' }
$manifestPath = $manifests[0].FullName
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$expectedIdentity = "https://github.com/usesesame/Sesame/.github/workflows/release-early-access.yml@refs/tags/v$($manifest.version)"
if ($manifest.source.repository -ne 'usesesame/Sesame' -or $manifest.source.workflow -ne '.github/workflows/release-early-access.yml' -or $manifest.source.ref -ne "refs/tags/v$($manifest.version)" -or $manifest.sigstore.issuer -ne 'https://token.actions.githubusercontent.com' -or $manifest.sigstore.certificateIdentity -ne $expectedIdentity) {
  throw 'The release manifest does not use the pinned Sesame Sigstore identity.'
}
if ($manifest.schemaVersion -ne 1 -or $manifest.product -ne 'Sesame' -or $manifest.releaseKind -ne 'unsigned-windows-early-access' -or $manifest.windowsTrust.authenticodeVerified -ne $false -or $manifest.windowsTrust.smartScreenReputationPromised -ne $false -or $manifest.windowsTrust.label -ne 'Unsigned Windows early-access build') {
  throw 'The release manifest has an invalid product or Windows trust disclosure.'
}
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$digest = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($digest -ne $manifest.artifact.sha256) { throw 'The installer SHA-256 does not match the release manifest.' }
Write-Host "SHA-256 verified: $digest"
if ($HashOnly) {
  Write-Warning 'Hash-only verification does not authenticate who published the manifest. Run without -HashOnly after installing Cosign for publisher verification.'
  exit 0
}
$cosign = Get-Command cosign -ErrorAction SilentlyContinue
if ($null -eq $cosign) { throw 'Cosign is required for publisher verification. Install Cosign or rerun explicitly with -HashOnly.' }
$manifestBundle = Join-Path $root "$($manifests[0].Name).sigstore.json"
$artifactBundle = Join-Path $root "$($manifest.artifact.filename).sigstore.json"
& $cosign.Source verify-blob $manifestPath --bundle $manifestBundle --certificate-identity $expectedIdentity --certificate-oidc-issuer $manifest.sigstore.issuer
if ($LASTEXITCODE -ne 0) { throw 'The release manifest Sigstore verification failed.' }
& $cosign.Source verify-blob $installerPath --bundle $artifactBundle --certificate-identity $expectedIdentity --certificate-oidc-issuer $manifest.sigstore.issuer
if ($LASTEXITCODE -ne 0) { throw 'The installer Sigstore verification failed.' }
$sbomPath = Join-Path $root $manifest.sbom.filename
$sbomDigest = (Get-FileHash -LiteralPath $sbomPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sbomDigest -ne $manifest.sbom.sha256 -or (Get-Item -LiteralPath $sbomPath).Length -ne $manifest.sbom.bytes) {
  throw 'The SBOM does not match the signed release manifest.'
}
$evidencePath = Join-Path $root 'sigstore-evidence.json'
$evidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json
$artifactBundleDigest = (Get-FileHash -LiteralPath $artifactBundle -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestBundleDigest = (Get-FileHash -LiteralPath $manifestBundle -Algorithm SHA256).Hash.ToLowerInvariant()
if ($evidence.verified -ne $true -or $evidence.transparencyLogVerified -ne $true -or $evidence.issuer -ne $manifest.sigstore.issuer -or $evidence.certificateIdentity -ne $expectedIdentity -or $evidence.artifactSha256 -ne $digest -or $evidence.artifactBundleSha256 -ne $artifactBundleDigest -or $evidence.manifestBundleSha256 -ne $manifestBundleDigest) {
  throw 'The normalized Sigstore evidence does not match the verified bundles.'
}
Write-Host "Sigstore release workflow verified for Sesame $($manifest.version)."
