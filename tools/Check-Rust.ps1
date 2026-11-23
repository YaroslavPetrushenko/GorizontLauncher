<#
  Local Rust check/build for the launcher on Windows when plain `cargo check` fails in C crates
  (ring, zstd-sys, lzma-sys: "stddef.h not found", D8050, LNK1104).

  Causes fixed here:
    1. The MSVC environment (INCLUDE/LIB) is not loaded -> load it from vcvars64.bat.
    2. Very long paths under src-tauri\target break cl.exe/lib.exe -> use a short CARGO_TARGET_DIR.

  Usage:  powershell -File tools\Check-Rust.ps1            # cargo check
          powershell -File tools\Check-Rust.ps1 test       # cargo test
#>
param([string]$Command = "check")
$ErrorActionPreference = "Stop"

$vcvars = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $vcvars) { throw "vcvars64.bat not found: install Visual Studio Build Tools (C++ workload)." }
foreach ($line in (cmd /c "`"$($vcvars.FullName)`" >nul 2>&1 && set")) {
  if ($line -match "^([^=]+)=(.*)$") { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process") }
}

New-Item -ItemType Directory -Force "C:\t\tgt" | Out-Null
$env:CARGO_TARGET_DIR = "C:\t\tgt"
$env:TEMP = "C:\t"; $env:TMP = "C:\t"

Push-Location (Join-Path $PSScriptRoot "..\src-tauri")
try { cargo $Command } finally { Pop-Location }
