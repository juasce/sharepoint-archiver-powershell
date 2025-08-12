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

### Azure DevOps Pipeline Setup

Follow this checklist to set up Azure DevOps for Phase 1 testing:

#### Prerequisites Checklist

**☐ 1. Azure Resources Setup**
- [ ] Azure Key Vault created and accessible
- [ ] Key Vault contains required secrets:
  - `azure-client-id` - Azure Entra app registration ID
  - `azure-tenant-id` - Azure AD tenant ID  
  - `cert-thumbprint` - Certificate thumbprint
  - `private-key-pem-content` - Certificate private key in PEM format
- [ ] Azure Storage Account created
- [ ] SharePoint site/library accessible

**☐ 2. Azure Entra App Registration**
- [ ] App registration created in Azure Entra ID
- [ ] Certificate uploaded to app registration
- [ ] SharePoint permissions granted to app:
  - `Sites.FullControl.All` (or `Sites.Read.All` for read-only testing)
- [ ] Azure Storage permissions configured (Storage Account Contributor role)

**☐ 3. Azure DevOps Project Setup**
- [ ] Azure DevOps project created
- [ ] Repository imported/connected
- [ ] Service connection created (see step 4)

**☐ 4. Create Azure Service Connection**
1. Go to Project Settings → Service connections
2. Click "New service connection"
3. Select "Azure Resource Manager"
4. Choose "Service principal (automatic)" or "Workload Identity federation"
5. Select your subscription and resource group
6. Name it `SharePoint-Archiver-ServiceConnection` (or update pipeline with your name)
7. Grant access to all pipelines
8. Verify the service connection has access to:
   - Key Vault (Key Vault Reader role)
   - Storage Account (Storage Account Contributor role)

**☐ 5. Pipeline Configuration**
1. Go to Pipelines → New pipeline
2. Select "Azure Repos Git" (or your source)
3. Select your repository
4. Choose "Existing Azure Pipelines YAML file"
5. Select `/azure-pipelines.yml`
6. Review pipeline parameters:
   - `sharepointUrl`: Your SharePoint site URL
   - `storageAccountName`: Your storage account name
   - `keyVaultName`: Your Key Vault name

**☐ 6. Pipeline Variables (Optional)**
Set these as pipeline variables if you prefer not to use parameters:
- `sharepointUrl`
- `storageAccountName` 
- `keyVaultName`

#### Running the Pipeline

**Manual Run:**
1. Go to Pipelines → Select your pipeline
2. Click "Run pipeline"
3. Set parameter values if using parameters
4. Click "Run"

**Automatic Triggers:**
Pipeline runs automatically on:
- Push to `main` or `develop` branches
- Pull requests to `main`
- Changes to `scripts/` folder or `azure-pipelines.yml`

#### Troubleshooting Setup

**Service Connection Issues:**
- Verify service principal has correct permissions
- Check subscription and resource group access
- Ensure service connection is authorized for your pipeline

**Key Vault Access Issues:**
- Verify Key Vault access policies include the service principal
- Check secret names match exactly (case-sensitive)
- Ensure Key Vault allows access from Azure services

**SharePoint Permission Issues:**
- Verify app registration has SharePoint API permissions
- Check certificate is not expired
- Ensure SharePoint URL is accessible from Azure

### Azure DevOps Pipeline Usage Example
```yaml
# This is handled automatically by azure-pipelines.yml
# No manual YAML needed - just run the pipeline
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