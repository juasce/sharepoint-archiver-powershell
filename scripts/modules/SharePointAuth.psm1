# SharePointAuth.psm1
# Authentication module for SharePoint and Azure Storage connections

#Requires -Modules Az.KeyVault, Az.Storage, Az.Accounts, PnP.PowerShell

function Get-KeyVaultSecrets {
    <#
    .SYNOPSIS
    Retrieves authentication secrets from Azure Key Vault
    
    .PARAMETER KeyVaultName
    Name of the Azure Key Vault containing the secrets
    
    .OUTPUTS
    Hashtable containing the authentication secrets
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyVaultName
    )
    
    try {
        Write-Host "Retrieving secrets from Key Vault: $KeyVaultName" -ForegroundColor Yellow
        
        $secrets = @{}
        
        # Get required secrets
        $secrets.ClientId = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "AZURE-CLIENT-ID" -AsPlainText)
        $secrets.TenantId = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "AZURE-TENANT-ID" -AsPlainText)
        $secrets.CertThumbprint = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "CERT-THUMBPRINT-00" -AsPlainText)
        $secrets.PrivateKeyPem = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "PRIVATE-KEY-PEM-CONTENT-00" -AsPlainText)
        
        # Validate all secrets were retrieved
        $requiredKeys = @('ClientId', 'TenantId', 'CertThumbprint', 'PrivateKeyPem')
        foreach ($key in $requiredKeys) {
            if ([string]::IsNullOrWhiteSpace($secrets[$key])) {
                throw "Required secret '$key' is missing or empty in Key Vault"
            }
        }
        
        Write-Host "Successfully retrieved all authentication secrets" -ForegroundColor Green
        return $secrets
    }
    catch {
        Write-Error "Failed to retrieve secrets from Key Vault '$KeyVaultName': $($_.Exception.Message)"
        throw
    }
}

function New-CertificateFromPem {
    <#
    .SYNOPSIS
    Creates a certificate object from PEM content
    
    .PARAMETER PrivateKeyPem
    PEM formatted private key content
    
    .PARAMETER CertThumbprint
    Certificate thumbprint for validation
    
    .OUTPUTS
    X509Certificate2 object for authentication
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrivateKeyPem,
        
        [Parameter(Mandatory = $true)]
        [string]$CertThumbprint
    )
    
    try {
        Write-Host "Creating certificate from PEM content" -ForegroundColor Yellow
        
        # Create temporary file for PEM content
        $tempPemFile = [System.IO.Path]::GetTempFileName()
        Set-Content -Path $tempPemFile -Value $PrivateKeyPem -Encoding UTF8
        
        try {
            # Create certificate from PEM file
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($tempPemFile)
            
            # Validate thumbprint matches
            if ($cert.Thumbprint -ne $CertThumbprint.Replace(" ", "").ToUpper()) {
                throw "Certificate thumbprint mismatch. Expected: $CertThumbprint, Actual: $($cert.Thumbprint)"
            }
            
            Write-Host "Certificate created successfully with thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
            return $cert
        }
        finally {
            # Clean up temporary file
            if (Test-Path $tempPemFile) {
                Remove-Item $tempPemFile -Force
            }
        }
    }
    catch {
        Write-Error "Failed to create certificate from PEM content: $($_.Exception.Message)"
        throw
    }
}

function Connect-SharePointOnline {
    <#
    .SYNOPSIS
    Connects to SharePoint Online using certificate authentication
    
    .PARAMETER SharePointUrl
    SharePoint site URL to connect to
    
    .PARAMETER ClientId
    Azure AD app registration client ID
    
    .PARAMETER TenantId
    Azure AD tenant ID
    
    .PARAMETER Certificate
    X509Certificate2 object for authentication
    
    .OUTPUTS
    Boolean indicating success of connection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    
    try {
        Write-Host "Connecting to SharePoint Online: $SharePointUrl" -ForegroundColor Yellow
        
        # Connect using certificate authentication
        Connect-PnPOnline -Url $SharePointUrl -ClientId $ClientId -Tenant $TenantId -Certificate $Certificate
        
        Write-Host "Successfully connected to SharePoint Online" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to SharePoint Online: $($_.Exception.Message)"
        throw
    }
}

function Get-AzureStorageContext {
    <#
    .SYNOPSIS
    Gets Azure Storage context using managed identity or current Azure session
    
    .PARAMETER StorageAccountName
    Name of the Azure Storage account
    
    .OUTPUTS
    Azure Storage context for operations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )
    
    try {
        Write-Host "Getting Azure Storage context for account: $StorageAccountName" -ForegroundColor Yellow
        
        # Get storage account using current Azure context (managed identity or authenticated session)
        $storageAccount = Get-AzStorageAccount | Where-Object { $_.StorageAccountName -eq $StorageAccountName }
        
        if (-not $storageAccount) {
            throw "Storage account '$StorageAccountName' not found or not accessible"
        }
        
        # Create storage context using managed identity/current authentication
        $ctx = $storageAccount.Context
        
        Write-Host "Successfully created Azure Storage context" -ForegroundColor Green
        return $ctx
    }
    catch {
        Write-Error "Failed to get Azure Storage context for '$StorageAccountName': $($_.Exception.Message)"
        throw
    }
}

function Test-SharePointConnection {
    <#
    .SYNOPSIS
    Tests SharePoint connection and validates access
    
    .PARAMETER SharePointUrl
    SharePoint site URL to test
    
    .OUTPUTS
    Boolean indicating if connection and access are valid
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointUrl
    )
    
    try {
        Write-Host "Testing SharePoint connection and access" -ForegroundColor Yellow
        
        # Test basic connection
        $web = Get-PnPWeb
        if (-not $web) {
            throw "Unable to retrieve web information from SharePoint"
        }
        
        Write-Host "SharePoint Web Title: $($web.Title)" -ForegroundColor Cyan
        Write-Host "SharePoint Web URL: $($web.Url)" -ForegroundColor Cyan
        
        # Test list access (try to get document libraries)
        $lists = Get-PnPList | Where-Object { $_.BaseTemplate -eq 101 }  # Document Libraries
        Write-Host "Found $($lists.Count) document libraries" -ForegroundColor Cyan
        
        if ($lists.Count -gt 0) {
            foreach ($list in $lists | Select-Object -First 3) {
                Write-Host "  - $($list.Title) ($($list.ItemCount) items)" -ForegroundColor Gray
            }
        }
        
        Write-Host "SharePoint connection test passed" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "SharePoint connection test failed: $($_.Exception.Message)"
        return $false
    }
}

function Test-AzureStorageConnection {
    <#
    .SYNOPSIS
    Tests Azure Storage connection and validates access
    
    .PARAMETER StorageContext
    Azure Storage context to test
    
    .PARAMETER StorageAccountName
    Storage account name for reference
    
    .OUTPUTS
    Boolean indicating if connection and access are valid
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.WindowsAzure.Commands.Storage.AzureStorageContext]$StorageContext,
        
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )
    
    try {
        Write-Host "Testing Azure Storage connection and access" -ForegroundColor Yellow
        
        # Test storage account access
        $containers = Get-AzStorageContainer -Context $StorageContext -MaxCount 10
        
        Write-Host "Storage Account: $StorageAccountName" -ForegroundColor Cyan
        Write-Host "Found $($containers.Count) containers" -ForegroundColor Cyan
        
        if ($containers.Count -gt 0) {
            foreach ($container in $containers | Select-Object -First 3) {
                Write-Host "  - $($container.Name) (Last Modified: $($container.LastModified))" -ForegroundColor Gray
            }
        }
        
        Write-Host "Azure Storage connection test passed" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Azure Storage connection test failed: $($_.Exception.Message)"
        return $false
    }
}

function Initialize-Authentication {
    <#
    .SYNOPSIS
    Initializes authentication for both SharePoint and Azure Storage
    
    .PARAMETER SharePointUrl
    SharePoint site URL to connect to
    
    .PARAMETER StorageAccountName
    Azure Storage account name
    
    .PARAMETER KeyVaultName
    Key Vault name containing authentication secrets
    
    .OUTPUTS
    Hashtable containing authentication contexts and results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName,
        
        [Parameter(Mandatory = $true)]
        [string]$KeyVaultName
    )
    
    try {
        Write-Host "Initializing authentication for SharePoint Archiver" -ForegroundColor Cyan
        Write-Host "SharePoint URL: $SharePointUrl" -ForegroundColor Gray
        Write-Host "Storage Account: $StorageAccountName" -ForegroundColor Gray
        Write-Host "Key Vault: $KeyVaultName" -ForegroundColor Gray
        
        $result = @{
            Success = $false
            SharePointConnected = $false
            StorageConnected = $false
            StorageContext = $null
            Errors = @()
        }
        
        # Step 1: Retrieve secrets from Key Vault
        Write-Host "`n--- Step 1: Retrieving Key Vault Secrets ---" -ForegroundColor Cyan
        $secrets = Get-KeyVaultSecrets -KeyVaultName $KeyVaultName
        
        # Step 2: Create certificate from PEM content
        Write-Host "`n--- Step 2: Creating Certificate ---" -ForegroundColor Cyan
        $certificate = New-CertificateFromPem -PrivateKeyPem $secrets.PrivateKeyPem -CertThumbprint $secrets.CertThumbprint
        
        # Step 3: Connect to SharePoint
        Write-Host "`n--- Step 3: Connecting to SharePoint ---" -ForegroundColor Cyan
        $sharePointConnected = Connect-SharePointOnline -SharePointUrl $SharePointUrl -ClientId $secrets.ClientId -TenantId $secrets.TenantId -Certificate $certificate
        $result.SharePointConnected = $sharePointConnected
        
        # Step 4: Test SharePoint connection
        Write-Host "`n--- Step 4: Testing SharePoint Access ---" -ForegroundColor Cyan
        $sharePointTest = Test-SharePointConnection -SharePointUrl $SharePointUrl
        
        # Step 5: Get Azure Storage context
        Write-Host "`n--- Step 5: Getting Azure Storage Context ---" -ForegroundColor Cyan
        $storageContext = Get-AzureStorageContext -StorageAccountName $StorageAccountName
        $result.StorageContext = $storageContext
        $result.StorageConnected = $true
        
        # Step 6: Test Azure Storage connection
        Write-Host "`n--- Step 6: Testing Azure Storage Access ---" -ForegroundColor Cyan
        $storageTest = Test-AzureStorageConnection -StorageContext $storageContext -StorageAccountName $StorageAccountName
        
        # Final validation
        $result.Success = $sharePointConnected -and $sharePointTest -and $result.StorageConnected -and $storageTest
        
        Write-Host "`n--- Authentication Summary ---" -ForegroundColor Cyan
        Write-Host "SharePoint Connected: $($result.SharePointConnected)" -ForegroundColor $(if ($result.SharePointConnected) { "Green" } else { "Red" })
        Write-Host "SharePoint Access Test: $sharePointTest" -ForegroundColor $(if ($sharePointTest) { "Green" } else { "Red" })
        Write-Host "Storage Connected: $($result.StorageConnected)" -ForegroundColor $(if ($result.StorageConnected) { "Green" } else { "Red" })
        Write-Host "Storage Access Test: $storageTest" -ForegroundColor $(if ($storageTest) { "Green" } else { "Red" })
        Write-Host "Overall Success: $($result.Success)" -ForegroundColor $(if ($result.Success) { "Green" } else { "Red" })
        
        return $result
    }
    catch {
        $result.Errors += $_.Exception.Message
        Write-Error "Authentication initialization failed: $($_.Exception.Message)"
        return $result
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Get-KeyVaultSecrets',
    'New-CertificateFromPem', 
    'Connect-SharePointOnline',
    'Get-AzureStorageContext',
    'Test-SharePointConnection',
    'Test-AzureStorageConnection',
    'Initialize-Authentication'
)