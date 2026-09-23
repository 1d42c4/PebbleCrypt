param([switch]$Offline)

$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $cargoArguments = @('--release', '--locked')
    if ($Offline) { $cargoArguments += '--offline' }

    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed.' }

    cargo clippy --all-targets @cargoArguments -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Clippy failed.' }

    cargo test @cargoArguments
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }

    Write-Host 'Formatting, Clippy, and all tests passed.'
} finally {
    Pop-Location
}
