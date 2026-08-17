[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Before,

  [Parameter(Mandatory = $true)]
  [string]$After,

  [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$beforeRoot = Resolve-Path -LiteralPath $Before
$afterRoot = Resolve-Path -LiteralPath $After
$beforeCsv = Join-Path $beforeRoot 'data-files.csv'
$afterCsv = Join-Path $afterRoot 'data-files.csv'

function Import-EvidenceCsv([string]$Path) {
  $header = Get-Content -LiteralPath $Path -TotalCount 1
  foreach ($requiredColumn in @('relativePath', 'length', 'lastWriteTimeUtc', 'sha256')) {
    if ($header -notmatch ('"' + [regex]::Escape($requiredColumn) + '"')) {
      throw "Evidence CSV '$Path' is missing required column '$requiredColumn'."
    }
  }
  return @(Import-Csv -LiteralPath $Path)
}

$beforeRows = @(Import-EvidenceCsv $beforeCsv)
$afterRows = @(Import-EvidenceCsv $afterCsv)
$beforeByPath = @{}
foreach ($row in $beforeRows) {
  if ($row.relativePath) { $beforeByPath[$row.relativePath] = $row }
}
$afterByPath = @{}
foreach ($row in $afterRows) {
  if ($row.relativePath) { $afterByPath[$row.relativePath] = $row }
}

$paths = @($beforeByPath.Keys + $afterByPath.Keys | Sort-Object -Unique)
$changes = @(foreach ($path in $paths) {
  $old = $beforeByPath[$path]
  $new = $afterByPath[$path]
  if (-not $old) {
    [pscustomobject][ordered]@{ relativePath = $path; status = 'Added'; beforeSha256 = ''; afterSha256 = $new.sha256 }
  } elseif (-not $new) {
    [pscustomobject][ordered]@{ relativePath = $path; status = 'Removed'; beforeSha256 = $old.sha256; afterSha256 = '' }
  } elseif ($old.sha256 -ne $new.sha256 -or $old.length -ne $new.length) {
    [pscustomobject][ordered]@{ relativePath = $path; status = 'Changed'; beforeSha256 = $old.sha256; afterSha256 = $new.sha256 }
  }
})

if (-not $OutputPath) {
  $OutputPath = Join-Path $afterRoot 'data-file-comparison.csv'
}
if ($changes.Count -eq 0) {
  '"relativePath","status","beforeSha256","afterSha256"' | Set-Content -Encoding utf8 -LiteralPath $OutputPath
  Write-Host 'No data-file additions, removals, or byte changes detected.'
} else {
  $changes | Export-Csv -NoTypeInformation -Encoding utf8 -LiteralPath $OutputPath
  Write-Host "$($changes.Count) data-file difference(s) written to $OutputPath"
  $changes | Format-Table -AutoSize
}
