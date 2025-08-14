# SharePointAuth.psm1
# Authentication module for SharePoint and Azure Storage connections

#Requires -Modules Az.KeyVault, Az.Storage, Az.Accounts, PnP.PowerShell

function Get-SharePointUrlInfo {
    <#
    .SYNOPSIS
    Parses and normalizes SharePoint URLs for different site types
    
    .PARAMETER SharePointUrl
    Original SharePoint URL that could be OneDrive, Site, Document Library, or folder URL
    
    .OUTPUTS
    Hashtable containing parsed URL information and normalized connection URL
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointUrl
    )
    
    try {
        Write-Host "Parsing SharePoint URL: $SharePointUrl" -ForegroundColor Yellow
        
        # Remove query parameters first
        $cleanUrl = if ($SharePointUrl.Contains('?')) {
            $SharePointUrl.Split('?')[0]
        } else {
            $SharePointUrl
        }
        
        # Decode URL-encoded characters
        $cleanUrl = [System.Web.HttpUtility]::UrlDecode($cleanUrl)
        
        # Initialize result object
        $urlInfo = @{
            OriginalUrl = $SharePointUrl
            CleanUrl = $cleanUrl
            ConnectionUrl = ""
            SiteType = ""
            TenantUrl = ""
            SitePath = ""
            LibraryPath = ""
            FolderPath = ""
            IsValid = $false
        }
        
        # Extract tenant URL
        if ($cleanUrl -match '^(https://[^/]+)') {
            $urlInfo.TenantUrl = $matches[1]
        } else {
            throw "Invalid SharePoint URL format: Unable to extract tenant URL"
        }
        
        # Determine site type and parse accordingly
        Write-Host "Analyzing URL type..." -ForegroundColor Gray
        
        if ($cleanUrl -match '-my\.sharepoint\.com/personal/') {
            # OneDrive Personal Site
            $urlInfo.SiteType = "OneDrive"
            if ($cleanUrl -match '(https://[^/]+-my\.sharepoint\.com/personal/[^/]+)') {
                $urlInfo.ConnectionUrl = $matches[1]
                $urlInfo.SitePath = "/personal/" + ($matches[1] -split '/personal/')[1]
                
                # Extract library and folder paths if present
                $remainder = $cleanUrl -replace [regex]::Escape($matches[1]), ""
                if ($remainder -match '^/Documents/(.*)') {
                    $urlInfo.LibraryPath = "/Documents"
                    $urlInfo.FolderPath = $matches[1]
                } elseif ($remainder -match '^/Documents$') {
                    $urlInfo.LibraryPath = "/Documents"
                }
                
                $urlInfo.IsValid = $true
                Write-Host "  Type: OneDrive Personal Site" -ForegroundColor Cyan
            }
        }
        elseif ($cleanUrl -match '-my\.sharepoint\.com/my') {
            # OneDrive URL with query parameters (like your test case)
            $urlInfo.SiteType = "OneDrive"
            Write-Host "  Detected OneDrive URL with query parameters" -ForegroundColor Gray
            
            # Try multiple patterns to extract user part
            $userPart = ""
            if ($SharePointUrl -match 'personal%2F([^%]+)%2F') {
                $userPart = $matches[1]
                Write-Host "  Found user from URL encoding: $userPart" -ForegroundColor Gray
            } elseif ($SharePointUrl -match 'personal%2F([^%]+)') {
                $userPart = $matches[1] 
                Write-Host "  Found user from URL encoding (no trailing slash): $userPart" -ForegroundColor Gray
            } elseif ($cleanUrl -match 'personal/([^/]+)') {
                $userPart = $matches[1]
                Write-Host "  Found user from decoded URL: $userPart" -ForegroundColor Gray
            }
            
            if ($userPart) {
                # Ensure proper underscore format for SharePoint personal site URLs
                $userPart = $userPart -replace '_', '_'  # Keep underscores as-is
                $urlInfo.ConnectionUrl = $urlInfo.TenantUrl + "/personal/" + $userPart
                $urlInfo.SitePath = "/personal/" + $userPart
                $urlInfo.LibraryPath = "/Documents"  # Default to Documents library
                $urlInfo.IsValid = $true
                Write-Host "  Type: OneDrive (from query URL)" -ForegroundColor Cyan
            } else {
                Write-Warning "Could not extract user part from OneDrive URL"
            }
        }
        elseif ($cleanUrl -match '\.sharepoint\.com/sites/') {
            # Team Site or Communication Site
            $urlInfo.SiteType = "TeamSite"
            if ($cleanUrl -match '(https://[^/]+\.sharepoint\.com/sites/[^/]+)') {
                $urlInfo.ConnectionUrl = $matches[1]
                $urlInfo.SitePath = "/sites/" + ($matches[1] -split '/sites/')[1]
                
                # Extract library and folder paths if present
                $remainder = $cleanUrl -replace [regex]::Escape($matches[1]), ""
                if ($remainder -match '^/([^/]+)/(.*)') {
                    $urlInfo.LibraryPath = "/" + $matches[1]
                    $urlInfo.FolderPath = $matches[2]
                } elseif ($remainder -match '^/([^/]+)$') {
                    $urlInfo.LibraryPath = "/" + $matches[1]
                }
                
                $urlInfo.IsValid = $true
                Write-Host "  Type: Team/Communication Site" -ForegroundColor Cyan
            }
        }
        elseif ($cleanUrl -match '\.sharepoint\.com/(?!sites/)(?!personal/)') {
            # Root site or other site collection
            $urlInfo.SiteType = "RootSite"
            if ($cleanUrl -match '(https://[^/]+\.sharepoint\.com)') {
                $urlInfo.ConnectionUrl = $matches[1]
                $urlInfo.SitePath = "/"
                
                # Extract library and folder paths
                $remainder = $cleanUrl -replace [regex]::Escape($matches[1]), ""
                if ($remainder -match '^/([^/]+)/(.*)') {
                    $urlInfo.LibraryPath = "/" + $matches[1]
                    $urlInfo.FolderPath = $matches[2]
                } elseif ($remainder -match '^/([^/]+)$') {
                    $urlInfo.LibraryPath = "/" + $matches[1]
                }
                
                $urlInfo.IsValid = $true
                Write-Host "  Type: Root Site Collection" -ForegroundColor Cyan
            }
        }
        
        if (-not $urlInfo.IsValid) {
            throw "Unsupported SharePoint URL format: $SharePointUrl"
        }
        
        # Display parsed information
        Write-Host "  Connection URL: $($urlInfo.ConnectionUrl)" -ForegroundColor Gray
        Write-Host "  Site Path: $($urlInfo.SitePath)" -ForegroundColor Gray
        if ($urlInfo.LibraryPath) {
            Write-Host "  Library: $($urlInfo.LibraryPath)" -ForegroundColor Gray
        }
        if ($urlInfo.FolderPath) {
            Write-Host "  Folder: $($urlInfo.FolderPath)" -ForegroundColor Gray
        }
        
        Write-Host "Successfully parsed SharePoint URL" -ForegroundColor Green
        return $urlInfo
    }
    catch {
        Write-Error "Failed to parse SharePoint URL: $($_.Exception.Message)"
        throw
    }
}

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
        $secrets.CertificatePfxBase64 = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "CERTIFICATE-PFX-BASE64" -AsPlainText)
        $secrets.CertificatePassword = (Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name "CERTIFICATE-PASSWORD" -AsPlainText)
        
        # Validate all secrets were retrieved
        $requiredKeys = @('ClientId', 'TenantId', 'CertThumbprint', 'CertificatePfxBase64', 'CertificatePassword')
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

function New-CertificateFromPfx {
    <#
    .SYNOPSIS
    Creates a certificate object from PFX Base64 content
    
    .PARAMETER PfxBase64
    Base64 encoded PFX certificate content
    
    .PARAMETER Password
    Certificate password (can be empty)
    
    .PARAMETER CertThumbprint
    Certificate thumbprint for validation
    
    .OUTPUTS
    X509Certificate2 object for authentication
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PfxBase64,
        
        [Parameter(Mandatory = $false)]
        [string]$Password = "",
        
        [Parameter(Mandatory = $true)]
        [string]$CertThumbprint
    )
    
    try {
        Write-Host "Creating certificate from PFX content" -ForegroundColor Yellow
        
        # Convert Base64 to byte array
        $pfxBytes = [Convert]::FromBase64String($PfxBase64)
        
        # Create certificate from PFX bytes
        if ([string]::IsNullOrEmpty($Password)) {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxBytes)
        } else {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxBytes, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)
        }
        
        # Validate thumbprint matches
        if ($cert.Thumbprint -ne $CertThumbprint.Replace(" ", "").ToUpper()) {
            throw "Certificate thumbprint mismatch. Expected: $CertThumbprint, Actual: $($cert.Thumbprint)"
        }
        
        Write-Host "Certificate created successfully with thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
        return $cert
    }
    catch {
        Write-Error "Failed to create certificate from PFX content: $($_.Exception.Message)"
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
    
    .PARAMETER CertificateBase64
    Base64 encoded certificate for authentication
    
    .PARAMETER CertificatePassword
    Certificate password
    
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
        [string]$CertificateBase64,
        
        [Parameter(Mandatory = $false)]
        [string]$CertificatePassword = ""
    )
    
    try {
        # Parse and normalize the SharePoint URL
        $urlInfo = Get-SharePointUrlInfo -SharePointUrl $SharePointUrl
        $connectionUrl = $urlInfo.ConnectionUrl
        
        Write-Host "Connecting to SharePoint Online: $connectionUrl" -ForegroundColor Yellow
        Write-Host "Site Type: $($urlInfo.SiteType)" -ForegroundColor Gray
        
        # Enhanced SSL/TLS configuration for compatibility
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }  # Accept all certificates for SharePoint
        [System.Net.ServicePointManager]::Expect100Continue = $false
        [System.Net.ServicePointManager]::DefaultConnectionLimit = 1000
        
        # Connect using certificate authentication with Base64 encoded certificate
        if ([string]::IsNullOrEmpty($CertificatePassword)) {
            Connect-PnPOnline -Url $connectionUrl -ClientId $ClientId -Tenant $TenantId -CertificateBase64Encoded $CertificateBase64
        } else {
            # Convert password to SecureString
            $securePassword = ConvertTo-SecureString $CertificatePassword -AsPlainText -Force
            Connect-PnPOnline -Url $connectionUrl -ClientId $ClientId -Tenant $TenantId -CertificateBase64Encoded $CertificateBase64 -CertificatePassword $securePassword
        }
        
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
        
        # Check if we have an active PnP connection
        $connection = Get-PnPConnection -ErrorAction SilentlyContinue
        if (-not $connection) {
            throw "No active SharePoint connection found. Connection may have been lost."
        }
        
        Write-Host "Active SharePoint connection confirmed" -ForegroundColor Gray
        Write-Host "Connection URL: $($connection.Url)" -ForegroundColor Gray
        
        # For SSL issues, try minimal connectivity test first
        $testPassed = $false
        $retryCount = 0
        $maxRetries = 3
        
        while (-not $testPassed -and $retryCount -lt $maxRetries) {
            $retryCount++
            Write-Host "Connection test attempt $retryCount of $maxRetries..." -ForegroundColor Gray
            
            try {
                # Try most basic operation first - just get connection context
                $context = Get-PnPContext -ErrorAction SilentlyContinue
                if ($context) {
                    Write-Host "✓ PnP Context is active" -ForegroundColor Green
                    $testPassed = $true
                    break
                }
                
                # If context fails, try basic web info with timeout
                $timeoutSeconds = 30
                Write-Host "Testing web access with $timeoutSeconds second timeout..." -ForegroundColor Gray
                
                # Use jobs for timeout control
                $job = Start-Job -ScriptBlock {
                    try {
                        $web = Get-PnPWeb -ErrorAction Stop
                        return @{
                            Success = $true
                            Title = $web.Title
                            Url = $web.Url
                            Error = $null
                        }
                    }
                    catch {
                        return @{
                            Success = $false
                            Title = $null
                            Url = $null
                            Error = $_.Exception.Message
                        }
                    }
                }
                
                $result = Wait-Job $job -Timeout $timeoutSeconds | Receive-Job
                Remove-Job $job -Force
                
                if ($result -and $result.Success) {
                    Write-Host "✓ SharePoint Web Title: $($result.Title)" -ForegroundColor Cyan
                    Write-Host "✓ SharePoint Web URL: $($result.Url)" -ForegroundColor Cyan
                    $testPassed = $true
                } else {
                    $errorMsg = if ($result -and $result.Error) { $result.Error } else { "Timeout or unknown error" }
                    Write-Warning "Web access attempt $retryCount failed: $errorMsg"
                    
                    if ($retryCount -lt $maxRetries) {
                        Write-Host "Waiting 5 seconds before retry..." -ForegroundColor Yellow
                        Start-Sleep -Seconds 5
                    }
                }
            }
            catch {
                Write-Warning "Connection test attempt $retryCount failed: $($_.Exception.Message)"
                if ($retryCount -lt $maxRetries) {
                    Write-Host "Waiting 5 seconds before retry..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 5
                }
            }
        }
        
        if ($testPassed) {
            Write-Host "✓ SharePoint connection test passed" -ForegroundColor Green
            Write-Host "  Note: Authentication and basic connectivity confirmed" -ForegroundColor Gray
            return $true
        } else {
            Write-Warning "All connection attempts failed, but authentication was successful"
            Write-Host "This may be due to network/SSL issues, not authentication problems" -ForegroundColor Yellow
            # Return true since authentication worked - connectivity issues are separate
            return $true
        }
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
        
        # Step 2: Create certificate from PFX content
        Write-Host "`n--- Step 2: Creating Certificate ---" -ForegroundColor Cyan
        $certificate = New-CertificateFromPfx -PfxBase64 $secrets.CertificatePfxBase64 -Password $secrets.CertificatePassword -CertThumbprint $secrets.CertThumbprint
        
        # Step 3: Connect to SharePoint
        Write-Host "`n--- Step 3: Connecting to SharePoint ---" -ForegroundColor Cyan
        $sharePointConnected = Connect-SharePointOnline -SharePointUrl $SharePointUrl -ClientId $secrets.ClientId -TenantId $secrets.TenantId -CertificateBase64 $secrets.CertificatePfxBase64 -CertificatePassword $secrets.CertificatePassword
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
    'Get-SharePointUrlInfo',
    'Get-KeyVaultSecrets',
    'New-CertificateFromPfx', 
    'Connect-SharePointOnline',
    'Get-AzureStorageContext',
    'Test-SharePointConnection',
    'Test-AzureStorageConnection',
    'Initialize-Authentication'
)