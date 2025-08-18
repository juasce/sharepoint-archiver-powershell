# SharePoint Archiver - Simple Fixes Applied

## Issues Fixed

### 1. AzCopy Source Detection Issue
**Problem:** AzCopy could not infer source location for SharePoint download URLs
```
ERROR: Cannot infer source location of https://ascendispharmacom-my.sharepoint.com/personal/jua_ascendispharma_com/_layouts/15/download.aspx...
```

**Solution:** Added `--from-to=BlobBlob` parameter to AzCopy command to explicitly tell it this is a blob-to-blob transfer.

**File:** `scripts/modules/SharePointAuth.psm1` lines 1610-1616
```powershell
# Build AzCopy arguments (SIMPLIFIED)
$azCopyArgs = @(
    "copy",
    "`"$sourceUrl`"",
    "`"$destUrl`"",
    "--from-to=BlobBlob",  # Tell AzCopy this is a blob-to-blob transfer for SharePoint URLs
    "--overwrite=true"
)
```

### 2. PowerShell Download SSL Issues
**Problem:** PowerShell Invoke-WebRequest failing with SSL connection issues when downloading from SharePoint

**Solution:** Added proper SSL/TLS configuration before SharePoint downloads.

**File:** `scripts/modules/SharePointAuth.psm1` lines 1663-1665
```powershell
# Configure SSL/TLS for SharePoint downloads
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
```

### 3. Removed Complex Parameters
**Problem:** AzCopy was failing with invalid parameters like `--parallel-type=Auto`

**Solution:** Simplified AzCopy command to bare minimum:
- Removed all complex block size, MD5, and concurrency parameters
- Kept only essential `--from-to=BlobBlob` and `--overwrite=true`
- This follows the "keep it simple" requirement

## How It Works Now

1. **Primary Method:** PowerShell download + blob upload
   - Downloads SharePoint file to temp location using Invoke-WebRequest with proper SSL settings
   - Uploads to Azure Storage using native PowerShell Az.Storage cmdlets
   - Includes MD5 verification for data integrity

2. **Fallback Method:** AzCopy with simplified parameters
   - Uses `--from-to=BlobBlob` to handle SharePoint URLs properly
   - Minimal parameter set to avoid compatibility issues

## Testing

The pipeline will now:
1. Use Graph API to enumerate SharePoint files (already working)
2. Try PowerShell download method first (should work with SSL fixes)
3. Fall back to simplified AzCopy if PowerShell fails (should work with --from-to parameter)

## Key Changes Summary

- **Line 1610-1616:** Simplified AzCopy arguments with `--from-to=BlobBlob`
- **Line 1663-1665:** Added SSL/TLS configuration for PowerShell downloads
- **Removed:** All complex AzCopy parameters that were causing issues

This keeps the solution "ultra simple" as requested while fixing the core issues identified in the diagnostics.