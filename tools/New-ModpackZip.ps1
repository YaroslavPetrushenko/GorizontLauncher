param(
  [Parameter(Mandatory = $true)] [string]$Source,
  [Parameter(Mandatory = $true)] [string]$PackVersion,
  [string]$Output = "modpack.zip",
  [string]$LoaderVersion = "266"
)

$ErrorActionPreference = "Stop"
$sourcePath = (Resolve-Path $Source).Path
$temp = Join-Path $env:TEMP ("gorizont-pack-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
  Copy-Item (Join-Path $sourcePath '*') $temp -Recurse -Force
  # Old client profiles are installed by the launcher itself; never ship them.
  $oldVersions = Join-Path $temp 'versions'
  if (Test-Path $oldVersions) { Remove-Item $oldVersions -Recurse -Force }
  $manifest = [ordered]@{
    schema_version = 1
    pack_id = 'gorizont'
    pack_version = $PackVersion
    minecraft_version = '1.21.1'
    loader = [ordered]@{ type = 'neoforge'; version = $LoaderVersion }
  }
  # Without a BOM: Windows PowerShell's "-Encoding UTF8" adds one and the launcher cannot read such a file.
  [IO.File]::WriteAllText((Join-Path $temp 'manifest.json'), ($manifest | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
  if (Test-Path $Output) { Remove-Item $Output -Force }
  Compress-Archive -Path (Join-Path $temp '*') -DestinationPath $Output -CompressionLevel Optimal
  Write-Host "Created $Output"
} finally {
  if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
}
