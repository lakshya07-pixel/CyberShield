$workspace = "E:\PROJECT\releases\stage_app_compatibility_20261022_183530"
$subdirs = @("inventory", "logs", "tests", "evidence", "reports", "hashes")

foreach ($sub in $subdirs) {
    $dirPath = Join-Path $workspace $sub
    if (-not (Test-Path $dirPath)) {
        New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
    }
}

Write-Host "Created workspace directories at $workspace"

