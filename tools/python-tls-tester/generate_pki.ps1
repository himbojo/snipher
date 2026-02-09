
# generate_pki.ps1
# Script to generate PKI for Python TLS Tester

$pythonPath = Get-Command python -ErrorAction SilentlyContinue

if (-not $pythonPath) {
    Write-Error "Python executable not found in PATH."
    exit 1
}

Write-Host "Checking for 'cryptography' library..."
try {
    python -c "import cryptography" 2>$null
} catch {
    Write-Host "Installing 'cryptography' library..."
    python -m pip install cryptography
}

Write-Host "Running pki_gen.py..."
python pki_gen.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "PKI Generation successful!"
} else {
    Write-Error "PKI Generation failed."
}
