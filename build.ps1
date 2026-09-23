$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    cargo build --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    cargo test --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    New-Item -ItemType Directory -Path 'dist' -Force | Out-Null
    Copy-Item -LiteralPath 'target\release\pebblecrypt.exe' -Destination 'dist\PebbleCrypt.exe'
    Write-Host 'Built dist\PebbleCrypt.exe'
} finally {
    Pop-Location
}
