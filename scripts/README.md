# SharePoint Archiver Scripts - Phase 1

This directory contains the Phase 1 implementation of the SharePoint Archiver POC, focusing on authentication and connection validation.

## Phase 1 Components

### SharePointAuth.psm1 Module

Located in `modules/SharePointAuth.psm1`, this module provides authentication functions for both SharePoint and Azure Storage.

**Key Functions:**
- `Get-KeyVaultSecrets` - Retrieves authentication secrets from Azure Key Vault
- `New-CertificateFromPem` - Creates certificate object from PEM content
- `Connect-SharePointOnline` - Connects to SharePoint using certificate authentication
- `Get-AzureStorageContext` - Gets Azure Storage context using managed identity
- `Test-SharePointConnection` - Validates SharePoint connection and access
- `Test-AzureStorageConnection` - Validates Azure Storage connection and access
- `Initialize-Authentication` - Main function that orchestrates full authentication flow

### Test-Authentication.ps1 Script

Main test script that validates all Phase 1 authentication components.

## Prerequisites

### PowerShell Modules
Install required modules before running:
```powershell
Install-Module Az.Accounts -Scope CurrentUser
Install-Module Az.KeyVault -Scope CurrentUser  
Install-Module Az.Storage -Scope CurrentUser
Install-Module PnP.PowerShell -Scope CurrentUser
```

### Azure Authentication
Ensure you're authenticated to Azure:
```powershell
# For local development
Connect-AzAccount

# For Azure DevOps (uses managed identity automatically)
# No action required - handled by pipeline
```

### Key Vault Setup
Your Azure Key Vault must contain these secrets:
- `azure-client-id` - Azure Entra app registration ID
- `azure-tenant-id` - Azure AD tenant ID
- `cert-thumbprint` - Certificate thumbprint
- `private-key-pem-content` - Certificate private key in PEM format

## Usage

### Local Testing
```powershell
# Navigate to scripts directory
cd scripts

# Run authentication test
.\Test-Authentication.ps1 -SharePointUrl "https://tenant.sharepoint.com/sites/test" -StorageAccountName "teststorage" -KeyVaultName "test-keyvault"
```

### Azure DevOps Pipeline Usage
```yaml
steps:
- task: PowerShell@2
  displayName: 'Test Authentication - Phase 1'
  inputs:
    filePath: 'scripts/Test-Authentication.ps1'
    arguments: >
      -SharePointUrl "$(sharepointUrl)"
      -StorageAccountName "$(storageAccountName)" 
      -KeyVaultName "$(keyVaultName)"
    pwsh: true
```

## Expected Output

Successful Phase 1 execution will show:
```
SharePoint Archiver - Authentication Test
========================================

--- Step 1: Checking PowerShell Module Requirements ---
✓ Az.Accounts v2.x.x - Azure authentication
✓ Az.KeyVault v4.x.x - Key Vault access
✓ Az.Storage v5.x.x - Storage account access  
✓ PnP.PowerShell v2.x.x - SharePoint connectivity

--- Step 2: Loading SharePoint Authentication Module ---
✓ SharePoint Authentication module loaded

--- Step 3: Checking Azure Connection ---
✓ Azure PowerShell connected
  Account: user@tenant.com
  Tenant: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Subscription: Test Subscription

--- Step 4: Running Authentication Test ---
...authentication steps...

--- Step 5: Test Results Summary ---
Overall Result: SUCCESS

--- Step 6: Phase 1 Success Criteria Validation ---
Phase 1 Success Criteria:
  ✓ Authenticate to SharePoint using certificate
  ✓ Retrieve and validate SharePoint site access
  ✓ Connect to Azure Storage using managed identity

Phase 1 Completion: 3/3 criteria met
🎉 Phase 1 POC Implementation Complete!
Ready to proceed to Phase 2: Single File Transfer
```

## Troubleshooting

### Common Issues

**Module Import Errors:**
- Ensure all required PowerShell modules are installed
- Check PowerShell execution policy: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

**Key Vault Access Denied:**
- Verify your Azure account has Key Vault Reader permissions
- Check Key Vault access policies include your identity
- Ensure Key Vault secrets exist with correct names

**SharePoint Connection Failures:**
- Verify certificate is valid and not expired
- Check Azure Entra app has SharePoint permissions
- Validate SharePoint URL is accessible

**Storage Account Access Issues:**
- Ensure your identity has Storage Account Contributor role
- Verify storage account exists in accessible subscription
- Check for network restrictions on storage account

### Debug Mode
Run with verbose output for troubleshooting:
```powershell
.\Test-Authentication.ps1 -SharePointUrl "..." -StorageAccountName "..." -KeyVaultName "..." -Verbose
```

## Phase 1 Success Criteria

✅ **Authenticate to SharePoint using certificate** - SharePointAuth module connects using Entra app + certificate from Key Vault

✅ **Retrieve and validate SharePoint site access** - Test script validates site access and enumerates document libraries

✅ **Connect to Azure Storage using managed identity** - Storage context created without access keys

## Next Steps

After Phase 1 completion, proceed to:
- **Phase 2**: Single File Transfer - Implement AzCopy integration for individual file transfers
- **Phase 3**: Folder Discovery - Recursive SharePoint content enumeration  
- **Phase 4**: Bulk Transfer - Multiple file transfers with progress reporting