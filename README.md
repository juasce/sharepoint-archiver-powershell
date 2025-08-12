# SharePoint Archiver - PowerShell Edition

A PowerShell-based solution for archiving SharePoint content to Azure Storage using AzCopy, designed for enterprise-scale transfers and complex folder structures.

## Overview

This application provides a robust alternative to existing SharePoint archiving solutions, specifically designed to handle:
- Large files (up to 50GB+)
- Complex folder hierarchies (50+ folders with subfolders)
- Bulk file transfers with parallel processing
- Enterprise authentication using federated identities

The solution leverages PowerShell and AzCopy to ensure reliable, resumable transfers while maintaining the original SharePoint folder structure in Azure Storage.

## Architecture

### Core Components
- **PowerShell Scripts**: Main orchestration and business logic
- **SharePoint PnP PowerShell**: Authentication and content discovery
- **AzCopy**: High-performance file transfers
- **Azure DevOps Pipeline**: Automated execution and parameter management

### Authentication Strategy
- **Production**: Workload Identity Federation (recommended)
- **Development**: Certificate-based authentication using Azure Key Vault
- **Storage Access**: Managed Identity or federated identity (no storage keys)

### Transfer Flow
```
SharePoint URL → Authentication → Content Discovery → File Enumeration → AzCopy Transfer → Verification
```

## Features

- **Scalable Architecture**: Handles enterprise-scale transfers
- **Folder Structure Preservation**: Maintains SharePoint hierarchy in blob storage
- **Large File Support**: Optimized for files up to 50GB+
- **Resume Capability**: Interrupted transfers can be resumed
- **Parallel Processing**: Configurable concurrent transfers
- **Comprehensive Logging**: Detailed progress and error reporting
- **Zero Local Storage**: Direct streaming transfers (no temp files)

## Project Structure

```
sharepoint-archiver-powershell/
├── scripts/
│   ├── Invoke-SharePointArchiver.ps1      # Main orchestration script
│   └── modules/
│       ├── SharePointAuth.psm1             # Authentication module
│       ├── SharePointDiscovery.psm1        # Content enumeration
│       ├── AzCopyManager.psm1              # Transfer operations
│       └── Logger.psm1                     # Logging utilities
├── azure-pipelines-powershell.yml         # Azure DevOps pipeline
├── docs/
│   └── POC-Implementation.md               # POC development guide
└── README.md                               # This file
```

## Getting Started

### Prerequisites

1. **PowerShell 5.1+** or **PowerShell Core 7+**
2. **AzCopy** installed and accessible in PATH
3. **SharePoint PnP PowerShell** module
4. **Azure PowerShell** modules
5. **Azure DevOps** self-hosted agent (for pipeline execution)

### Authentication Requirements

**For Development:**
- Azure AD App Registration with SharePoint permissions
- Certificate stored in Azure Key Vault
- Access to target Azure Storage accounts

**For Production:**
- Workload Identity Federation configured
- Managed Identity with appropriate permissions
- Azure DevOps service connection setup

## Usage

### Azure DevOps Pipeline

The solution is designed to run via Azure DevOps pipeline with the following parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `sharepointUrl` | SharePoint site, library, or folder URL | `https://tenant.sharepoint.com/sites/dept/Documents` |
| `storageAccountName` | Destination storage account name | `archivestorage001` |
| `containerName` | Target container (created if doesn't exist) | `dept-archive-2024` |
| `maxConcurrency` | Maximum concurrent transfers | `10` |

### Manual Execution

```powershell
# Navigate to scripts directory
cd scripts

# Execute main script with parameters
.\Invoke-SharePointArchiver.ps1 -SharePointUrl "https://tenant.sharepoint.com/sites/dept/Documents" -StorageAccountName "archivestorage001" -ContainerName "dept-archive-2024"
```

## Configuration

### Pipeline Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AZURE_TENANT_ID` | Azure AD tenant ID | Yes |
| `AZURE_CLIENT_ID` | App registration client ID | Yes |
| `KEYVAULT_NAME` | Key vault name for secrets | Yes |

### Key Vault Secrets

| Secret Name | Description |
|-------------|-------------|
| `azure-client-id` | SharePoint app registration ID |
| `azure-tenant-id` | Azure AD tenant ID |
| `cert-thumbprint` | Authentication certificate thumbprint |
| `private-key-pem-content` | Certificate private key (PEM format) |

## Performance Considerations

### Large File Handling
- **Streaming Transfers**: No local temp storage required
- **Resume Support**: Interrupted large file transfers can continue
- **Memory Efficient**: Minimal memory footprint during transfers

### Bulk Operations
- **Parallel Processing**: Configurable concurrency levels
- **Batch Operations**: Efficient handling of multiple small files
- **Progress Tracking**: Real-time transfer statistics

### Network Optimization
- **AzCopy Optimization**: Leverages AzCopy's built-in performance features
- **Adaptive Throughput**: Automatically adjusts based on network conditions
- **Retry Logic**: Handles transient network issues

## Error Handling

### Logging Levels
- **Information**: Progress updates and milestones
- **Warning**: Non-critical issues that don't stop execution
- **Error**: Critical failures requiring attention
- **Debug**: Detailed troubleshooting information

### Recovery Mechanisms
- **Automatic Retry**: Transient failures are automatically retried
- **Partial Success**: Reports successful transfers even if some files fail
- **Failed File Manifest**: Lists files that couldn't be transferred for manual review

## Security

### Authentication Security
- **Certificate-based**: Secure certificate storage in Key Vault
- **Federated Identity**: Eliminates long-lived secrets (recommended)
- **Least Privilege**: Minimal required permissions

### Data Security
- **In-Transit Encryption**: All transfers use HTTPS
- **Storage Encryption**: Data encrypted at rest in Azure Storage
- **No Local Copies**: Direct streaming prevents local data exposure

## Monitoring and Troubleshooting

### Pipeline Monitoring
- Detailed execution logs in Azure DevOps
- Transfer progress and statistics
- Error reporting with actionable information

### Common Issues
- **Authentication Failures**: Check certificate expiration and permissions
- **Network Timeouts**: Adjust concurrency levels for network conditions
- **SharePoint Access**: Verify URL accessibility and permissions

## Development Roadmap

### Phase 1: POC (Current)
- Basic authentication and connection
- Single file transfer capability
- Folder enumeration
- Basic error handling

### Phase 2: Production Features
- Bulk transfer optimization
- Advanced retry logic
- Comprehensive logging
- Performance monitoring

### Phase 3: Enterprise Features
- Incremental archiving support
- Notification systems
- Advanced reporting
- Multi-tenant support

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with appropriate tests
4. Submit a pull request with detailed description

## Support

For issues and questions:
1. Check the troubleshooting section in this README
2. Review pipeline execution logs
3. Create an issue in the repository with detailed information

## License

This project is licensed under the MIT License - see the LICENSE file for details.