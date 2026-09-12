# Verify Documentation Drift
# Usage: pwsh scripts/verify_docs_drift.ps1

$ErrorActionPreference = "Stop"
$driftFound = $false

Write-Host "Verifying documentation synchronization and drift..." -ForegroundColor Cyan

# 1. Verify docs directory exists
$docsDir = Join-Path $PSScriptRoot "..\docs"
if (-not (Test-Path $docsDir)) {
    Write-Error "Docs directory not found at $docsDir"
    exit 1
}

# 2. Check for emoji violations across documentation
Write-Host "[1/3] Checking for forbidden characters and emojis in documentation..." -ForegroundColor Gray
$docFiles = Get-ChildItem -Path $docsDir -Filter "*.md" -Recurse
$emojiPattern = "[\uD83C-\uDBFF\uDC00-\uDFFF\u2600-\u27BF]"

foreach ($file in $docFiles) {
    $content = Get-Content -Path $file.FullName -Raw -Encoding utf8
    if ($content -match $emojiPattern) {
        Write-Host "FAIL: Emoji character found in $($file.FullName)" -ForegroundColor Red
        $driftFound = $true
    }
}

# 3. Check Builtin Plugins coverage in docs
Write-Host "[2/3] Checking builtin plugin coverage in documentation..." -ForegroundColor Gray
$pluginSourceDir = Join-Path $PSScriptRoot "..\internal\plugins\builtin"
if (Test-Path $pluginSourceDir) {
    $plugins = Get-ChildItem -Path $pluginSourceDir -Filter "*.go" | Where-Object { $_.Name -notlike "*_test.go" }
    $pluginSdkDoc = Join-Path $docsDir "plugin_sdk.md"
    if (Test-Path $pluginSdkDoc) {
        $sdkDocContent = Get-Content -Path $pluginSdkDoc -Raw -Encoding utf8
        foreach ($plugin in $plugins) {
            $baseName = $plugin.BaseName
            if ($sdkDocContent -notmatch "(?i)$baseName") {
                Write-Host "WARN: Builtin plugin '$baseName' not explicitly mentioned in plugin_sdk.md" -ForegroundColor Yellow
            }
        }
    }
}

# 4. Check API route synchronization in api_reference.md
Write-Host "[3/3] Checking OpenAPI endpoint synchronization in api_reference.md..." -ForegroundColor Gray
$apiRefDoc = Join-Path $docsDir "api_reference.md"
$openapiSource = Join-Path $PSScriptRoot "..\internal\api\openapi.go"

if ((Test-Path $apiRefDoc) -and (Test-Path $openapiSource)) {
    $openapiContent = Get-Content -Path $openapiSource -Raw -Encoding utf8
    $apiRefContent = Get-Content -Path $apiRefDoc -Raw -Encoding utf8

    # Extract paths from OpenAPI spec
    $matches = [regex]::Matches($openapiContent, '"(/api/v1/[a-zA-Z0-9_\-/{}/]+)":')
    foreach ($m in $matches) {
        $path = $m.Groups[1].Value
        # Replace parameterized path segments for doc search
        $cleanPath = $path -replace '\{[a-zA-Z0-9_]+\}', ''
        if ($apiRefContent -notmatch [regex]::Escape($cleanPath)) {
            Write-Host "WARN: Endpoint '$path' may be missing from api_reference.md" -ForegroundColor Yellow
        }
    }
}

if ($driftFound) {
    Write-Host "FAILED: Documentation drift or policy violations detected." -ForegroundColor Red
    exit 1
} else {
    Write-Host "SUCCESS: Documentation is synchronized and compliant with project standards." -ForegroundColor Green
    exit 0
}
