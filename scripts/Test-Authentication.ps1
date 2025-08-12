# Test-Authentication.ps1
# Basic connection test script for SharePoint Archiver Phase 1

<#
.SYNOPSIS
Tests authentication and connection to SharePoint and Azure Storage

.DESCRIPTION
This script validates the authentication components built in Phase 1 of the SharePoint Archiver POC.
It tests connections to SharePoint using certificate-based authentication and Azure Storage using 
managed identity or current Azure session.

.PARAMETER SharePointUrl
SharePoint site, library, or folder URL to test connection against

.PARAMETER StorageAccountName  
Azure Storage account name to test connection against

.PARAMETER KeyVaultName
Azure Key Vault name containing authentication secrets

.EXAMPLE
.\Test-Authentication.ps1 -SharePointUrl "https://tenant.sharepoint.com/sites/test" -StorageAccountName "teststorage" -KeyVaultName "test-keyvault"

.EXAMPLE
# Test with pipeline-style parameters
.\Test-Authentication.ps1 -SharePointUrl $env:SHAREPOINT_URL -StorageAccountName $env:STORAGE_ACCOUNT -KeyVaultName $env:KEYVAULT_NAME
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "SharePoint site URL to test")]
    [ValidateScript({
        if ($_ -match '^https://.*\.sharepoint\.com/') {
            return $true
        }
        throw "SharePoint URL must be a valid https://tenant.sharepoint.com/ URL"
    })]
    [string]$SharePointUrl,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure Storage account name")]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory = $true, HelpMessage = "Azure Key Vault name")]
    [ValidatePattern('^[a-zA-Z0-9\-]{3,24}$')]
    [string]$KeyVaultName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Skip Azure PowerShell connection check")]
    [switch]$SkipAzureConnection
)

# Set error action preference for the script
$ErrorActionPreference = 'Stop'

# Import required modules
$ModulePath = Join-Path -Path $PSScriptRoot -ChildPath "modules\SharePointAuth.psm1"

Write-Host "SharePoint Archiver - Authentication Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

try {
    # Check if running in Azure DevOps or local environment
    $isAzureDevOps = $env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI -ne $null
    Write-Host "Execution Environment: $(if ($isAzureDevOps) { 'Azure DevOps' } else { 'Local/Manual' })" -ForegroundColor Yellow
    
    # Step 1: Validate required modules are available
    Write-Host "`n--- Step 1: Checking PowerShell Module Requirements ---" -ForegroundColor Cyan
    
    $requiredModules = @(
        @{ Name = 'Az.Accounts'; Purpose = 'Azure authentication' },
        @{ Name = 'Az.KeyVault'; Purpose = 'Key Vault access' }, 
        @{ Name = 'Az.Storage'; Purpose = 'Storage account access' },
        @{ Name = 'PnP.PowerShell'; Purpose = 'SharePoint connectivity' }
    )
    
    $moduleIssues = @()
    foreach ($module in $requiredModules) {
        $installed = Get-Module -ListAvailable -Name $module.Name
        if ($installed) {
            $version = $installed | Sort-Object Version -Descending | Select-Object -First 1
            Write-Host "✓ $($module.Name) v$($version.Version) - $($module.Purpose)" -ForegroundColor Green
        } else {
            Write-Host "✗ $($module.Name) - $($module.Purpose) [MISSING]" -ForegroundColor Red
            $moduleIssues += $module.Name
        }
    }
    
    if ($moduleIssues.Count -gt 0) {
        Write-Host "`nMissing required modules. Install with:" -ForegroundColor Yellow
        foreach ($module in $moduleIssues) {
            Write-Host "  Install-Module $module -Scope CurrentUser" -ForegroundColor Gray
        }
        throw "Required PowerShell modules are not installed"
    }
    
    # Step 2: Load SharePoint Authentication module
    Write-Host "`n--- Step 2: Loading SharePoint Authentication Module ---" -ForegroundColor Cyan
    
    if (-not (Test-Path $ModulePath)) {
        throw "SharePointAuth module not found at: $ModulePath"
    }
    
    Import-Module $ModulePath -Force
    Write-Host "✓ SharePoint Authentication module loaded" -ForegroundColor Green
    
    # Step 3: Check Azure connection
    Write-Host "`n--- Step 3: Checking Azure Connection ---" -ForegroundColor Cyan
    
    if (-not $SkipAzureConnection) {
        try {
            $azContext = Get-AzContext
            if ($azContext) {
                Write-Host "✓ Azure PowerShell connected" -ForegroundColor Green
                Write-Host "  Account: $($azContext.Account.Id)" -ForegroundColor Gray
                Write-Host "  Tenant: $($azContext.Tenant.Id)" -ForegroundColor Gray
                Write-Host "  Subscription: $($azContext.Subscription.Name)" -ForegroundColor Gray
            } else {
                Write-Host "⚠ Not connected to Azure. Attempting managed identity..." -ForegroundColor Yellow
                Connect-AzAccount -Identity -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Warning "Azure connection check failed: $($_.Exception.Message)"
            Write-Host "Continuing with authentication test..." -ForegroundColor Yellow
        }
    } else {
        Write-Host "⚠ Skipping Azure connection check" -ForegroundColor Yellow
    }
    
    # Step 4: Run authentication initialization
    Write-Host "`n--- Step 4: Running Authentication Test ---" -ForegroundColor Cyan
    
    $authResult = Initialize-Authentication -SharePointUrl $SharePointUrl -StorageAccountName $StorageAccountName -KeyVaultName $KeyVaultName
    
    # Step 5: Generate test report
    Write-Host "`n--- Step 5: Test Results Summary ---" -ForegroundColor Cyan
    
    $testResults = @{
        Timestamp = Get-Date
        SharePointUrl = $SharePointUrl
        StorageAccountName = $StorageAccountName
        KeyVaultName = $KeyVaultName
        ExecutionEnvironment = if ($isAzureDevOps) { 'Azure DevOps' } else { 'Local' }
        ModulesAvailable = $requiredModules.Count - $moduleIssues.Count
        ModulesMissing = $moduleIssues.Count
        SharePointConnected = $authResult.SharePointConnected
        StorageConnected = $authResult.StorageConnected
        OverallSuccess = $authResult.Success
        Errors = $authResult.Errors
    }
    
    Write-Host "Test Execution Summary:" -ForegroundColor White
    Write-Host "  Timestamp: $($testResults.Timestamp)" -ForegroundColor Gray
    Write-Host "  SharePoint URL: $($testResults.SharePointUrl)" -ForegroundColor Gray
    Write-Host "  Storage Account: $($testResults.StorageAccountName)" -ForegroundColor Gray
    Write-Host "  Key Vault: $($testResults.KeyVaultName)" -ForegroundColor Gray
    Write-Host "  Environment: $($testResults.ExecutionEnvironment)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Module Status:" -ForegroundColor White
    Write-Host "  Available: $($testResults.ModulesAvailable)/4" -ForegroundColor $(if ($testResults.ModulesMissing -eq 0) { 'Green' } else { 'Yellow' })
    Write-Host "  Missing: $($testResults.ModulesMissing)" -ForegroundColor $(if ($testResults.ModulesMissing -eq 0) { 'Green' } else { 'Red' })
    Write-Host ""
    Write-Host "Connection Status:" -ForegroundColor White
    Write-Host "  SharePoint: $($testResults.SharePointConnected)" -ForegroundColor $(if ($testResults.SharePointConnected) { 'Green' } else { 'Red' })
    Write-Host "  Azure Storage: $($testResults.StorageConnected)" -ForegroundColor $(if ($testResults.StorageConnected) { 'Green' } else { 'Red' })
    Write-Host ""
    Write-Host "Overall Result: $(if ($testResults.OverallSuccess) { 'SUCCESS' } else { 'FAILED' })" -ForegroundColor $(if ($testResults.OverallSuccess) { 'Green' } else { 'Red' })
    
    if ($testResults.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "Errors encountered:" -ForegroundColor Red
        foreach ($error in $testResults.Errors) {
            Write-Host "  • $error" -ForegroundColor Red
        }
    }
    
    # Step 6: Phase 1 completion validation
    Write-Host "`n--- Step 6: Phase 1 Success Criteria Validation ---" -ForegroundColor Cyan
    
    $phase1Criteria = @(
        @{ Name = 'Authenticate to SharePoint using certificate'; Met = $authResult.SharePointConnected },
        @{ Name = 'Retrieve and validate SharePoint site access'; Met = $authResult.SharePointConnected },
        @{ Name = 'Connect to Azure Storage using managed identity'; Met = $authResult.StorageConnected }
    )
    
    Write-Host "Phase 1 Success Criteria:" -ForegroundColor White
    $criteriaMet = 0
    foreach ($criteria in $phase1Criteria) {
        $status = if ($criteria.Met) { '✓' } else { '✗' }
        $color = if ($criteria.Met) { 'Green' } else { 'Red' }
        Write-Host "  $status $($criteria.Name)" -ForegroundColor $color
        if ($criteria.Met) { $criteriaMet++ }
    }
    
    Write-Host ""
    Write-Host "Phase 1 Completion: $criteriaMet/$($phase1Criteria.Count) criteria met" -ForegroundColor $(if ($criteriaMet -eq $phase1Criteria.Count) { 'Green' } else { 'Yellow' })
    
    if ($criteriaMet -eq $phase1Criteria.Count) {
        Write-Host ""
        Write-Host "🎉 Phase 1 POC Implementation Complete!" -ForegroundColor Green
        Write-Host "Ready to proceed to Phase 2: Single File Transfer" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "⚠ Phase 1 partially complete. Address remaining issues before proceeding." -ForegroundColor Yellow
    }
    
    # Return success/failure code for pipeline usage
    if ($testResults.OverallSuccess) {
        exit 0
    } else {
        exit 1
    }
}
catch {
    Write-Error "Authentication test failed: $($_.Exception.Message)"
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}
finally {
    # Cleanup: Disconnect from SharePoint if connected
    try {
        if (Get-PnPConnection -ErrorAction SilentlyContinue) {
            Disconnect-PnPOnline
            Write-Host "Disconnected from SharePoint" -ForegroundColor Gray
        }
    }
    catch {
        # Ignore cleanup errors
    }
}