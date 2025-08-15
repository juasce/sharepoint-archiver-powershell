# Test-GraphAPI.ps1
# Test script specifically for Microsoft Graph API file enumeration

#Requires -Modules Az.Accounts, Az.KeyVault

param(
    [Parameter(Mandatory = $false)]
    [string]$SharePointUrl = "https://ascendispharmacom-my.sharepoint.com/personal/jua",
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName = "kv-sp-archiver-dev-01"
)

# Import the SharePoint Auth module
$moduleManifest = Join-Path $PSScriptRoot "modules\SharePointAuth.psm1"
Import-Module $moduleManifest -Force

Write-Host "=== Microsoft Graph API Test ===" -ForegroundColor Cyan
Write-Host "Testing Graph API enumeration without PnP PowerShell" -ForegroundColor Yellow
Write-Host ""

try {
    # Step 1: Initialize Authentication (but skip PnP connection)
    Write-Host "Step 1: Getting Azure authentication context..." -ForegroundColor Cyan
    $azContext = Get-AzContext
    if (-not $azContext) {
        Write-Error "No Azure context found. Please authenticate first."
        exit 1
    }
    Write-Host "✓ Azure context available" -ForegroundColor Green
    Write-Host "  Account: $($azContext.Account.Id)" -ForegroundColor Gray
    Write-Host "  Subscription: $($azContext.Subscription.Name)" -ForegroundColor Gray
    Write-Host ""
    
    # Step 2: Test Graph Token
    Write-Host "Step 2: Testing Graph API access token..." -ForegroundColor Cyan
    try {
        $token = Get-GraphAccessToken
        Write-Host "✓ Graph access token obtained successfully" -ForegroundColor Green
        Write-Host "  Token length: $($token.Length) characters" -ForegroundColor Gray
    }
    catch {
        Write-Host "✗ Failed to get Graph token: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    
    # Step 3: Test Site ID Resolution
    Write-Host "Step 3: Testing SharePoint site ID resolution..." -ForegroundColor Cyan
    try {
        $siteInfo = Get-SharePointSiteId -SharePointUrl $SharePointUrl -AccessToken $token
        Write-Host "✓ Site information resolved" -ForegroundColor Green
        Write-Host "  Site ID: $($siteInfo.SiteId)" -ForegroundColor Gray
        Write-Host "  Drive ID: $($siteInfo.DriveId)" -ForegroundColor Gray
        Write-Host "  Site Type: $($siteInfo.SiteType)" -ForegroundColor Gray
    }
    catch {
        Write-Host "✗ Failed to get site ID: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Error details: $($_.ErrorDetails.Message)" -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    
    # Step 4: Test File Enumeration via Graph
    Write-Host "Step 4: Testing file enumeration via Graph API..." -ForegroundColor Cyan
    try {
        $files = Get-SharePointFilesViaGraph -SharePointUrl $SharePointUrl
        Write-Host "✓ File enumeration successful" -ForegroundColor Green
        Write-Host "  Files found: $($files.Count)" -ForegroundColor Gray
        
        if ($files.Count -gt 0) {
            Write-Host ""
            Write-Host "Sample files:" -ForegroundColor Gray
            foreach ($file in $files | Select-Object -First 5) {
                $sizeMB = [math]::Round($file.Size / 1MB, 2)
                Write-Host "  - $($file.Name) ($sizeMB MB)" -ForegroundColor Gray
            }
            
            if ($files.Count -gt 5) {
                Write-Host "  ... and $($files.Count - 5) more files" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "✗ File enumeration failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Error details: $($_.ErrorDetails.Message)" -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    
    # Step 5: Test with complex URL (if provided as parameter)
    if ($args.Count -gt 0 -and $args[0] -ne $SharePointUrl) {
        $complexUrl = $args[0]
        Write-Host "Step 5: Testing with complex URL..." -ForegroundColor Cyan
        Write-Host "  URL: $complexUrl" -ForegroundColor Gray
        
        try {
            $files = Get-SharePointFilesViaGraph -SharePointUrl $complexUrl
            Write-Host "✓ Complex URL enumeration successful" -ForegroundColor Green
            Write-Host "  Files found: $($files.Count)" -ForegroundColor Gray
        }
        catch {
            Write-Host "✗ Complex URL enumeration failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    Write-Host "=== Graph API Test Results ===" -ForegroundColor Cyan
    Write-Host "✓ Graph Access Token: PASSED" -ForegroundColor Green
    Write-Host "✓ Site ID Resolution: PASSED" -ForegroundColor Green
    Write-Host "✓ File Enumeration: PASSED" -ForegroundColor Green
    Write-Host ""
    Write-Host "✅ Microsoft Graph API is working as expected!" -ForegroundColor Green
    Write-Host "This can replace PnP PowerShell for file enumeration." -ForegroundColor Yellow
    
}
catch {
    Write-Error "Graph API test failed: $($_.Exception.Message)"
    exit 1
}