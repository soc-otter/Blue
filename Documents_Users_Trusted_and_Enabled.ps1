<#

.SYNOPSIS
This script digs into the registry for Microsoft Office Trusted Documents and spits out a CSV detailing trust status, file info, SHA256 hashes, timestamps, and Zone.Identifier 3 ADS info if it's there.

Zone.Identifier is an alternate data stream (ADS) created by Windows on NTFS and ReFS file systems to tag files downloaded from the internet or other potentially untrusted sources, commonly known as the "Mark of the Web" (MotW). This stream includes a ZoneTransfer::ZoneId value, such as 3 for internet-sourced files, as part of the Windows security zone system. Windows, along with supported applications like web browsers, email clients, and file transfer utilities, attaches this stream when a file is downloaded or received. The process involves the application using Windows APIs, such as IAttachmentExecute or IZoneIdentifier, to set the appropriate zone information. ADS like Zone.Identifier are specific to NTFS and ReFS and are not visible in standard file listings, meaning they can exist without being immediately noticed. These streams persist when files are moved or copied within the same volume but may be lost when transferred to non-supporting file systems or during certain file operations. The Zone.Identifier stream, or MotW, not only includes the ZoneId but can also contain additional metadata such as the referrer URL, HostUrl, and LastWriterPackageFamilyName to provide more context about the file's origin.

.DESCRIPTION
The script does a few things:
- Scans the HKU registry hive for Trusted Documents in Microsoft Office.
- Cleans up and resolves file paths (trims whitespace, expands env vars, decodes URI stuff).
- Checks for Zone.Identifier ADS for some extra details.
- Finally, wraps it all up in a CSV file.

.NOTES
File Version: 2.5
Works with: PowerShell 5.1 or higher, with the right permissions for registry and file system.
Dependencies: System.Web (for URL decoding)

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Documents_Users_Trusted_and_Enabled.ps1

.Example
PS> .\Documents_Users_Trusted_and_Enabled.ps1

#>

# Define the base directory for storing the output
$outputDirectory = 'C:\BlueTeam'

# Static name for the output file
$outputCsvFilePath = Join-Path -Path $outputDirectory -ChildPath 'Documents_Users_Trusted_and_Enabled.csv'

# Make sure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Write-Progress -Activity "Collecting Trusted Documents" -Status "Starting up" -PercentComplete 10

# Load the URL decoding assembly
Add-Type -AssemblyName System.Web

# Get the hostname of the machine
$hostname = $env:COMPUTERNAME

# Function to resolve paths with environment variables and URI-encoded characters
function Resolve-DocumentPath {
    param (
        [string]$documentPath
    )

    # Decode URL-encoded characters (e.g., %20 -> space)
    $decodedPath = [System.Web.HttpUtility]::UrlDecode($documentPath)

    # Strip common URL prefixes like 'file:///', 'file://', 'http://', 'https://'
    $pathWithoutPrefix = $decodedPath -replace '^file:\/\/\/|^file:\/\/|^https?:\/\/', ''

    # Expand environment variables in the path
    $resolvedPath = [Environment]::ExpandEnvironmentVariables($pathWithoutPrefix)

    # Replace forward slashes with backslashes for Windows paths
    return $resolvedPath -replace '\/', '\'
}

# This array will hold our registry data
$trustedDocumentsData = @()

# Pattern to match relevant registry data
$registryDataPattern = '^(?<FileName>\s*.+?)\s{2,}(?<RegistryType>REG_BINARY)\s{2,}(?<BinaryData>.+)$'

# Grab the registry keys for Office Trusted Documents
$trustedDocumentRegistryKeys = Get-ChildItem 'REGISTRY::HKU\*\Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords' -ErrorAction SilentlyContinue

foreach ($registryKey in $trustedDocumentRegistryKeys) {
    # Query each registry key
    $registryQueryResult = reg query $registryKey.Name

    # Split the result into lines for processing
    $queryLines = $registryQueryResult -split "`r`n"

    # Process each line in the result
    foreach ($line in $queryLines) {
        # Match lines with the regex pattern
        if ($line -match $registryDataPattern) {
            # Extract the file name and binary data, then clean up the file name
            $FileName = $matches['FileName'].Trim()
            $BinaryData = $matches['BinaryData']

            # Resolve the full and clean path of the file once
            $resolvedFilePath = Resolve-DocumentPath -documentPath $FileName

            # Set up placeholders for ADS info
            $zoneId = '-'
            $downloadLink = '-'
            $referrerUrl = '-'

            # Check for Zone.Identifier ADS after the path is resolved
            try {
                $adsContent = Get-Content -Path $resolvedFilePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
                if ($adsContent -and ($adsContent -match '^ZoneId=3')) {
                    foreach ($line in $adsContent) {
                        if ($line -match '^HostUrl=(.+)') {
                            $downloadLink = $matches[1]
                        }
                        if ($line -match '^ReferrerUrl=(.+)') {
                            $referrerUrl = $matches[1]
                        }
                    }
                    $zoneId = 3
                }
            } catch {
                # Move on if there’s an issue
            }

            # Add the file info and ADS data to the array
            $trustedDocumentsData += [PSCustomObject]@{
                FileName    = $resolvedFilePath
                BinaryData  = $BinaryData
                DownloadLink= $downloadLink
                ReferrerUrl = $referrerUrl
                ZoneId      = $zoneId
            }
        }
    }
}

# Makes file sizes look pretty
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB) {
        $Size /= 1KB
        $UnitIndex++
    }
    "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
}

# Gets file details
function Get-DocumentFileInfo {
    param (
        [string]$documentPath
    )
    try {
        $fileInfo = Get-Item $documentPath -ErrorAction Stop
        $acl = Get-Acl $documentPath

        return @{
            SHA256Hash     = (Get-FileHash -Algorithm SHA256 -Path $documentPath).Hash
            CreationTime   = $fileInfo.CreationTime.ToString('o')
            LastAccessTime = $fileInfo.LastAccessTime.ToString('o')
            LastWriteTime  = $fileInfo.LastWriteTime.ToString('o')
            FileSize       = Get-FormattedByteSize -ByteSize $fileInfo.Length
            Owner          = $acl.Owner
        }
    } catch {
        return @{
            SHA256Hash     = '-'
            CreationTime   = '-'
            LastAccessTime = '-'
            LastWriteTime  = '-'
            FileSize       = '-'
            Owner          = '-'
        }
    }
}

# Array to hold the CSV rows
$csvRows = @()

# Process each trusted document entry
foreach ($documentEntry in $trustedDocumentsData) {
    # Figure out editing and content enabled status from binary data
    $editingEnabled = $false
    $contentEnabled = $false

    if ($documentEntry.BinaryData -match 'FFFFFF7F') {
        $editingEnabled = $true
        $contentEnabled = $true
    } elseif ($documentEntry.BinaryData -match '01000000') {
        $editingEnabled = $true
        $contentEnabled = $false
    }

    # Get file details
    $fileInfo = Get-DocumentFileInfo -documentPath $documentEntry.FileName

    # Add everything to the CSV rows
    $csvRows += [PSCustomObject]@{
        Hostname        = $hostname
        FileName        = $documentEntry.FileName
        Owner           = $fileInfo.Owner
        FileSize        = $fileInfo.FileSize
        EditingEnabled  = $editingEnabled
        ContentEnabled  = $contentEnabled
        SHA256Hash      = $fileInfo.SHA256Hash
        ReferrerUrl     = $documentEntry.ReferrerUrl
        DownloadLink    = $documentEntry.DownloadLink
        CreationTime    = $fileInfo.CreationTime
        LastAccessTime  = $fileInfo.LastAccessTime
        LastWriteTime   = $fileInfo.LastWriteTime
        ZoneId          = $documentEntry.ZoneId
        BinaryData      = $documentEntry.BinaryData
    }
}

# Export everything to a CSV file
$csvRows | Export-Csv -Path $outputCsvFilePath -NoTypeInformation

Write-Progress -Activity "Collecting Trusted Documents" -Status "All done!" -PercentComplete 100
