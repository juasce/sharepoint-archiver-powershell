# Test-PnPDiagnostics.ps1
# Diagnostic script to test PnP operations step by step

#Requires -Modules Az.Accounts, Az.KeyVault, PnP.PowerShell

param(
    [Parameter(Mandatory = $false)]
    [string]$SharePointUrl = "https://ascendispharmacom-my.sharepoint.com/personal/jua",
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName = "kv-sp-archiver-dev-01"
)

# Import the SharePoint Auth module
$moduleManifest = Join-Path $PSScriptRoot "modules\SharePointAuth.psm1"
Import-Module $moduleManifest -Force

Write-Host "=== PnP Diagnostics Test ===" -ForegroundColor Cyan
Write-Host "Testing each PnP operation individually" -ForegroundColor Yellow
Write-Host ""

try {
    # Step 1: Initialize Authentication
    Write-Host "Step 1: Authentication" -ForegroundColor Cyan
    $authResult = Initialize-Authentication -SharePointUrl $SharePointUrl -StorageAccountName "stdaardevmedicalaffairs" -KeyVaultName $KeyVaultName
    
    if (-not $authResult.Success) {
        Write-Error "Authentication failed"
        exit 1
    }
    Write-Host "✓ Authentication successful" -ForegroundColor Green
    Write-Host ""
    
    # Step 2: Test Basic Context
    Write-Host "Step 2: Testing PnP Context" -ForegroundColor Cyan
    try {
        $context = Get-PnPContext
        Write-Host "✓ Get-PnPContext works" -ForegroundColor Green
        Write-Host "  Site URL: $($context.Url)" -ForegroundColor Gray
        Write-Host "  Web Title: $($context.Web.Title)" -ForegroundColor Gray
    }
    catch {
        Write-Host "✗ Get-PnPContext failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Step 3: Test Web Access
    Write-Host "Step 3: Testing Get-PnPWeb" -ForegroundColor Cyan
    try {
        $web = Get-PnPWeb
        Write-Host "✓ Get-PnPWeb works" -ForegroundColor Green
        Write-Host "  Web Title: $($web.Title)" -ForegroundColor Gray
        Write-Host "  Web URL: $($web.Url)" -ForegroundColor Gray
    }
    catch {
        Write-Host "✗ Get-PnPWeb failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Full error: $($_.Exception.ToString())" -ForegroundColor Red
    }
    Write-Host ""
    
    # Step 4: Test List Access
    Write-Host "Step 4: Testing Get-PnPList" -ForegroundColor Cyan
    try {
        Write-Host "Attempting to get all lists..." -ForegroundColor Gray
        $lists = Get-PnPList
        Write-Host "✓ Get-PnPList works - Found $($lists.Count) lists" -ForegroundColor Green
        
        # Show first few lists
        foreach ($list in $lists | Select-Object -First 3) {
            Write-Host "  - $($list.Title) ($($list.BaseTemplate))" -ForegroundColor Gray
        }
        
        # Try to get Documents library specifically
        Write-Host "Attempting to get Documents library..." -ForegroundColor Gray
        $docLib = Get-PnPList -Identity "Documents"
        Write-Host "✓ Documents library found: $($docLib.Title)" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ Get-PnPList failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Full error: $($_.Exception.ToString())" -ForegroundColor Red
    }
    Write-Host ""
    
    # Step 5: Test List Items (Simple)
    Write-Host "Step 5: Testing Get-PnPListItem (Simple)" -ForegroundColor Cyan
    try {
        Write-Host "Getting first 1 item from Documents..." -ForegroundColor Gray
        $items = Get-PnPListItem -List "Documents" -PageSize 1
        Write-Host "✓ Get-PnPListItem works - Retrieved $($items.Count) items" -ForegroundColor Green
        
        if ($items.Count -gt 0) {
            $item = $items[0]
            Write-Host "  First item: $($item['FileLeafRef']) (Type: $($item.FileSystemObjectType))" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "✗ Get-PnPListItem failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Full error: $($_.Exception.ToString())" -ForegroundColor Red
        Write-Host "  Inner exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Step 6: Test Folder Items
    Write-Host "Step 6: Testing Get-PnPFolderItem" -ForegroundColor Cyan
    try {
        Write-Host "Getting items from Documents root..." -ForegroundColor Gray
        $folderItems = Get-PnPFolderItem -FolderSiteRelativeUrl "/Documents" -ItemType File
        Write-Host "✓ Get-PnPFolderItem works - Retrieved $($folderItems.Count) files" -ForegroundColor Green
        
        if ($folderItems.Count -gt 0) {
            foreach ($item in $folderItems | Select-Object -First 3) {
                Write-Host "  - $($item.Name) ($([math]::Round($item.Length / 1MB, 2)) MB)" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "✗ Get-PnPFolderItem failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Full error: $($_.Exception.ToString())" -ForegroundColor Red
        Write-Host "  Inner exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Step 7: SSL Configuration Test
    Write-Host "Step 7: Testing with Enhanced SSL Configuration" -ForegroundColor Cyan
    try {
        Write-Host "Applying enhanced SSL settings..." -ForegroundColor Gray
        
        # More aggressive SSL configuration
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [System.Net.ServicePointManager]::Expect100Continue = $false
        [System.Net.ServicePointManager]::DefaultConnectionLimit = 100
        [System.Net.ServicePointManager]::MaxServicePointIdleTime = 10000
        [System.Net.ServicePointManager]::UseNagleAlgorithm = $false
        [System.Net.ServicePointManager]::CheckCertificateRevocationList = $false
        
        Write-Host "Retrying Get-PnPListItem with enhanced SSL..." -ForegroundColor Gray
        $items = Get-PnPListItem -List "Documents" -PageSize 1
        Write-Host "✓ Enhanced SSL worked - Retrieved $($items.Count) items" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ Enhanced SSL still failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Step 8: Environment Information
    Write-Host "Step 8: Environment Information" -ForegroundColor Cyan
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "PnP.PowerShell Version: $(Get-Module PnP.PowerShell -ListAvailable | Select-Object -First 1 | ForEach-Object { $_.Version })" -ForegroundColor Gray
    Write-Host "OS Version: $([System.Environment]::OSVersion.VersionString)" -ForegroundColor Gray
    Write-Host "TLS Protocols: $([System.Net.ServicePointManager]::SecurityProtocol)" -ForegroundColor Gray
    Write-Host "Azure DevOps: $($env:TF_BUILD)" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "=== Diagnostics Complete ===" -ForegroundColor Cyan
}
catch {
    Write-Error "Diagnostic test failed: $($_.Exception.Message)"
}
finally {
    try {
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore cleanup errors
    }
}