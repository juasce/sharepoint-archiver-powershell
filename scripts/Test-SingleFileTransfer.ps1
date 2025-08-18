# Test-SingleFileTransfer.ps1
# Test script for Phase 2 single file transfer functionality

#Requires -Modules Az.Accounts, Az.KeyVault, Az.Storage

param(
    [Parameter(Mandatory = $false)]
    [string]$SharePointUrl = "https://bcbsla-my.sharepoint.com/my/",
    
    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName = "stdaardevmedicalaffairs",
    
    [Parameter(Mandatory = $false)]
    [string]$ContainerName = "medicalinformation",
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName = "kv-sp-archiver-dev-01",
    
    [Parameter(Mandatory = $false)]
    [switch]$Recursive = $false,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxConcurrency = 5
)

# Import the SharePoint Auth module
$moduleManifest = Join-Path $PSScriptRoot "modules\SharePointAuth.psm1"
if (-not (Test-Path $moduleManifest)) {
    Write-Error "SharePointAuth module not found at: $moduleManifest"
    exit 1
}

Import-Module $moduleManifest -Force

try {
    Write-Host "=== SharePoint Archiver - Phase 2 Single File Transfer Test ===" -ForegroundColor Cyan
    Write-Host "Test Parameters:" -ForegroundColor Yellow
    Write-Host "  SharePoint URL: $SharePointUrl" -ForegroundColor Gray
    Write-Host "  Storage Account: $StorageAccountName" -ForegroundColor Gray
    Write-Host "  Container: $ContainerName" -ForegroundColor Gray
    Write-Host "  Key Vault: $KeyVaultName" -ForegroundColor Gray
    Write-Host "  Recursive: $Recursive" -ForegroundColor Gray
    Write-Host "  Max Concurrency: $MaxConcurrency" -ForegroundColor Gray
    Write-Host ""
    
    # Step 1: Initialize Authentication (Graph API mode - skip PnP PowerShell)
    Write-Host "Step 1: Initializing Authentication..." -ForegroundColor Cyan
    try {
        # Just get Azure storage context - Graph API handles SharePoint authentication
        Write-Host "Getting Key Vault secrets..." -ForegroundColor Gray
        $secrets = Get-KeyVaultSecrets -KeyVaultName $KeyVaultName
        
        Write-Host "Setting up Azure Storage context..." -ForegroundColor Gray
        $storageContext = Get-AzureStorageContext -StorageAccountName $StorageAccountName
        
        Write-Host "Testing Azure Storage connection..." -ForegroundColor Gray
        $storageTest = Test-AzureStorageConnection -StorageContext $storageContext -ContainerName $ContainerName
        
        if (-not $storageTest) {
            Write-Error "Azure Storage connection test failed"
            exit 1
        }
        
        Write-Host "✓ Authentication successful (Graph API mode)" -ForegroundColor Green
        Write-Host "✓ Azure Storage accessible" -ForegroundColor Green
    }
    catch {
        Write-Error "Authentication failed: $($_.Exception.Message)"
        exit 1
    }
    Write-Host ""
    
    # Step 2: Test File Enumeration (using Graph API)
    Write-Host "Step 2: Testing File Enumeration..." -ForegroundColor Cyan
    try {
        Write-Host "Using Graph API for file enumeration (PnP PowerShell bypassed due to SSL issues)" -ForegroundColor Yellow
        $files = Get-SharePointFilesViaGraph -SharePointUrl $SharePointUrl -Recursive:$Recursive
        Write-Host "✓ File enumeration completed - Found $($files.Count) files" -ForegroundColor Green
        
        if ($files.Count -eq 0) {
            Write-Warning "No files found to transfer. Test will end here."
            Write-Host "Consider using a SharePoint URL that contains files for testing." -ForegroundColor Yellow
            exit 0
        }
        
        # Show sample files
        Write-Host "Sample files found:" -ForegroundColor Gray
        foreach ($file in $files | Select-Object -First 3) {
            $sizeMB = [math]::Round($file.Size / 1MB, 2)
            Write-Host "  - $($file.Name) ($sizeMB MB)" -ForegroundColor Gray
        }
        if ($files.Count -gt 3) {
            Write-Host "  ... and $($files.Count - 3) more files" -ForegroundColor Gray
        }
    }
    catch {
        Write-Error "File enumeration failed: $($_.Exception.Message)"
        exit 1
    }
    Write-Host ""
    
    # Step 3: Test Path Mapping
    Write-Host "Step 3: Testing Path Mapping..." -ForegroundColor Cyan
    try {
        $testFile = $files[0]  # Use first file for testing
        $blobPath = Convert-SharePointPathToBlobPath -SharePointFile $testFile -SharePointUrl $SharePointUrl -ContainerName $ContainerName
        Write-Host "✓ Path mapping successful" -ForegroundColor Green
        Write-Host "  Example mapping:" -ForegroundColor Gray
        Write-Host "    SharePoint: $($testFile.ServerRelativeUrl)" -ForegroundColor Gray
        Write-Host "    Blob Path: $blobPath" -ForegroundColor Gray
    }
    catch {
        Write-Error "Path mapping failed: $($_.Exception.Message)"
        exit 1
    }
    Write-Host ""
    
    # Step 4: Prompt for Transfer Test
    Write-Host "Step 4: File Transfer Test" -ForegroundColor Cyan
    Write-Host "Ready to test actual file transfer using AzCopy." -ForegroundColor Yellow
    Write-Host "This will attempt to transfer $($files.Count) files to Azure Storage." -ForegroundColor Yellow
    Write-Host ""
    
    # For testing, limit to 1 file unless explicitly requested
    if ($files.Count -gt 1 -and -not $Recursive) {
        Write-Host "Limiting test to first file only (use -Recursive to transfer all files)" -ForegroundColor Yellow
        $files = $files | Select-Object -First 1
    }
    
    # Auto-proceed for automated pipeline execution
    # Check if running in Azure DevOps (has TF_BUILD environment variable)
    if ($env:TF_BUILD -eq "True") {
        Write-Host "Running in Azure DevOps pipeline - auto-proceeding with file transfer test" -ForegroundColor Yellow
        $response = 'y'
    } else {
        $response = Read-Host "Proceed with file transfer test? (y/N)"
    }
    
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-Host "File transfer test skipped by user." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Test Summary:" -ForegroundColor Cyan
        Write-Host "  ✓ Authentication: PASSED" -ForegroundColor Green
        Write-Host "  ✓ File Enumeration: PASSED" -ForegroundColor Green
        Write-Host "  ✓ Path Mapping: PASSED" -ForegroundColor Green
        Write-Host "  ? File Transfer: SKIPPED" -ForegroundColor Yellow
        exit 0
    }
    
    # Step 5: Execute File Transfer
    Write-Host "Step 5: Executing File Transfer..." -ForegroundColor Cyan
    try {
        $transferResult = Start-SingleFileTransfer -SharePointUrl $SharePointUrl -StorageAccountName $StorageAccountName -ContainerName $ContainerName -MaxConcurrency $MaxConcurrency -Recursive:$Recursive
        
        Write-Host ""
        Write-Host "=== FINAL TEST RESULTS ===" -ForegroundColor Cyan
        Write-Host "Authentication: ✓ PASSED" -ForegroundColor Green
        Write-Host "File Enumeration: ✓ PASSED" -ForegroundColor Green
        Write-Host "Path Mapping: ✓ PASSED" -ForegroundColor Green
        
        if ($transferResult.Success) {
            Write-Host "File Transfer: ✓ PASSED" -ForegroundColor Green
            Write-Host ""
            Write-Host "Transfer Results:" -ForegroundColor Gray
            Write-Host "  Files Found: $($transferResult.FilesFound)" -ForegroundColor Gray
            Write-Host "  Files Transferred: $($transferResult.FilesTransferred)" -ForegroundColor Gray
            Write-Host "  Files Failed: $($transferResult.FilesFailed)" -ForegroundColor Gray
            Write-Host "  Total Duration: $($transferResult.TransferDuration.ToString('mm\:ss'))" -ForegroundColor Gray
            
            Write-Host ""
            Write-Host "✓ Phase 2 Single File Transfer Test: ALL TESTS PASSED" -ForegroundColor Green
        } else {
            Write-Host "File Transfer: ✗ FAILED" -ForegroundColor Red
            Write-Host ""
            Write-Host "Transfer Results:" -ForegroundColor Gray
            Write-Host "  Files Found: $($transferResult.FilesFound)" -ForegroundColor Gray
            Write-Host "  Files Transferred: $($transferResult.FilesTransferred)" -ForegroundColor Gray
            Write-Host "  Files Failed: $($transferResult.FilesFailed)" -ForegroundColor Gray
            
            if ($transferResult.Errors.Count -gt 0) {
                Write-Host ""
                Write-Host "Errors:" -ForegroundColor Red
                foreach ($error in $transferResult.Errors) {
                    Write-Host "  - $error" -ForegroundColor Red
                }
            }
            
            Write-Host ""
            Write-Host "✗ Phase 2 Single File Transfer Test: TRANSFER FAILED" -ForegroundColor Red
            exit 1
        }
    }
    catch {
        Write-Error "File transfer execution failed: $($_.Exception.Message)"
        Write-Host ""
        Write-Host "=== FINAL TEST RESULTS ===" -ForegroundColor Cyan
        Write-Host "Authentication: ✓ PASSED" -ForegroundColor Green
        Write-Host "File Enumeration: ✓ PASSED" -ForegroundColor Green
        Write-Host "Path Mapping: ✓ PASSED" -ForegroundColor Green
        Write-Host "File Transfer: ✗ FAILED" -ForegroundColor Red
        Write-Host ""
        Write-Host "✗ Phase 2 Single File Transfer Test: TRANSFER FAILED" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Error "Test script failed: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "✗ Phase 2 Single File Transfer Test: FAILED" -ForegroundColor Red
    exit 1
}
finally {
    # Cleanup
    try {
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore cleanup errors
    }
}