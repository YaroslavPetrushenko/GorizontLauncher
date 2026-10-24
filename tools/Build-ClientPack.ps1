param(
  [Parameter(Mandatory = $true)] [string]$Profile,
  [Parameter(Mandatory = $true)] [string]$BaseModsZip,
  [string]$Output = "modpack.zip"
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$staging = Join-Path $env:TEMP ('gorizont-client-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging | Out-Null
try {
  [IO.Compression.ZipFile]::ExtractToDirectory((Resolve-Path $BaseModsZip), $staging)
  foreach ($dir in @('config','resourcepacks','shaderpacks','schematics','defaultconfigs')) {
    $source = Join-Path $Profile $dir
    if (Test-Path $source) { Copy-Item $source (Join-Path $staging $dir) -Recurse -Force }
  }
  $profileMods = Join-Path $Profile 'mods'
  if (Test-Path $profileMods) { Copy-Item (Join-Path $profileMods '*') (Join-Path $staging 'mods') -Force }
  $version = Join-Path $staging 'versions\Create(VOID)'
  New-Item -ItemType Directory -Path $version -Force | Out-Null
  Copy-Item (Join-Path $Profile 'Create(VOID).jar') $version -Force
  Copy-Item (Join-Path $Profile 'Create(VOID).json') $version -Force
  $manifest = @"
{
  ""schema_version"": 1,
  ""pack_id"": ""gorizont"",
  ""pack_version"": ""2.0.0"",
  ""minecraft_version"": ""1.21.1"",
  ""loader"": { ""type"": ""neoforge"", ""version"": ""248"" }
}
"@
  Set-Content (Join-Path $staging 'manifest.json') $manifest -Encoding UTF8
  if (Test-Path $Output) { Remove-Item $Output -Force }
  [IO.Compression.ZipFile]::CreateFromDirectory($staging, (Join-Path (Get-Location) $Output), [IO.Compression.CompressionLevel]::Optimal, $false)
} finally { if (Test-Path $staging) { Remove-Item $staging -Recurse -Force } }
Get-Item (Join-Path (Get-Location) $Output)
