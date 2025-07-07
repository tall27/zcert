# Simple script to revoke certificates by ID from search output
Write-Host "Searching for certificates with CN 1.1.1.1 and status VALID..." -ForegroundColor Yellow

$searchOutput = .\zcert search --cn 1.1.1.1 --status valid --wide

Write-Host "Found certificates. Processing..." -ForegroundColor Green

$searchOutput | ForEach-Object {
    # Extract ID from the line - look for UUID pattern only
    if ($_ -match '^([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})') {
        $id = $matches[1]
        Write-Host "Revoking certificate: $id" -ForegroundColor Cyan
        
        try {
            $result = .\zcert revoke --id $id --force 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  ✓ Successfully revoked $id" -ForegroundColor Green
            }
            else {
                Write-Host "  ✗ Failed to revoke $id" -ForegroundColor Red
                Write-Host "    Error: $result" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "  ✗ Exception revoking $id : $($_.Exception.Message)" -ForegroundColor Red
        }
        
        # Small delay between requests
        Start-Sleep -Milliseconds 200
    }
}

Write-Host "Completed processing all certificates." -ForegroundColor Green 