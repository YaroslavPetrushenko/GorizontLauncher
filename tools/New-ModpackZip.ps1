param(
  [Parameter(Mandatory = $true)] [string]$Source,
  [Parameter(Mandatory = $true)] [string]$PackVersion,
  [string]$Output = "modpack.zip"
)

$ErrorActionPreference = "Stop"
$sourcePath = (Resolve-Path $Source).Path
$temp = Join-Path $env:TEMP ("gorizont-pack-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
  Copy-Item (Join-Path $sourcePath '*') $temp -Recurse -Force
  $manifest = [ordered]@{
    schema_version = 1
    pack_id = 'gorizont'
    pack_version = $PackVersion
    minecraft_version = '1.21.1'
    loader = [ordered]@{ type = 'neoforge'; version = '248' }
  }
  $manifest | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $temp 'manifest.json') -Encoding UTF8
  if (Test-Path $Output) { Remove-Item $Output -Force }
  Compress-Archive -Path (Join-Path $temp '*') -DestinationPath $Output -CompressionLevel Optimal
  Write-Host "Created $Output"
} finally {
  if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
}
