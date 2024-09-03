<#

.SYNOPSIS
Finds trusted Microsoft Office documents from the registry and generates a CSV. When a user trusts a document enought to open and edit or run embedded content, those documents are stored in registgry.

.DESCRIPTION
This script searches the registry for trusted Microsoft Office documents, retrieves detailed metadata (file info, hash, timestamps), and checks for additional details such as Zone.Identifier 3 Alternate Data Stream (ADS). It helps detect potential adversarial behavior by examining documents that users have marked as trusted thereby providing insight into potentially malicious files. The results are output to a CSV.

.NOTES
Requires PowerShell v5+ and admin permissions.
Dependencies: System.Web (for URL decoding)

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Documents_Users_Trusted_and_Enabled.ps1

.EXAMPLE
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
        [string]$documentPath,
        [string]$username
    )

    try {
        # Decode URL-encoded characters (e.g., %20 -> space)
        $decodedPath = [System.Web.HttpUtility]::UrlDecode($documentPath)

        # Strip 'file://' prefix if present
        $pathWithoutPrefix = $decodedPath -replace '^file:/{2,3}', ''

        # Handle URLs and UNC paths
        if ($pathWithoutPrefix -match '^(https?:\/\/|\\\\)') {
            return $pathWithoutPrefix  # Return URLs and UNC paths as-is
        }

        # Define user-specific environment variables
        $userEnvVars = @(
            '%USERPROFILE%',
            '%APPDATA%',
            '%LOCALAPPDATA%',
            '%HOMEPATH%',
            '%HOMEDRIVE%',
            '%TEMP%',
            '%TMP%'
        )

        # Create a hashtable for variable replacements
        $replacements = @{}

        foreach ($var in $userEnvVars) {
            $varName = $var.Trim('%')
            switch ($varName) {
                'USERPROFILE' { $replacements[$var] = "C:\Users\$username" }
                'APPDATA' { $replacements[$var] = "C:\Users\$username\AppData\Roaming" }
                'LOCALAPPDATA' { $replacements[$var] = "C:\Users\$username\AppData\Local" }
                'HOMEPATH' { $replacements[$var] = "\Users\$username" }
                'HOMEDRIVE' { $replacements[$var] = "C:" }
                'TEMP' { $replacements[$var] = "C:\Users\$username\AppData\Local\Temp" }
                'TMP' { $replacements[$var] = "C:\Users\$username\AppData\Local\Temp" }
            }
        }

        # Replace user-specific environment variables
        $resolvedPath = $pathWithoutPrefix
        foreach ($key in $replacements.Keys) {
            $resolvedPath = $resolvedPath -replace [regex]::Escape($key), $replacements[$key]
        }

        # Replace any other environment variables
        $resolvedPath = [Environment]::ExpandEnvironmentVariables($resolvedPath)

        # Normalize path separators (replace forward slashes with backslashes)
        $resolvedPath = $resolvedPath -replace '/', '\'

        # Ensure proper backslash usage (replace multiple backslashes with a single one)
        $resolvedPath = $resolvedPath -replace '\\+', '\'

        # Remove any leading or trailing whitespace
        $resolvedPath = $resolvedPath.Trim()

        # If the path doesn't start with a drive letter and wasn't modified by user-specific vars, prepend the user profile path
        if (-not ($resolvedPath -match '^[A-Za-z]:' -or $resolvedPath -match '^\\\\' -or ($userEnvVars | Where-Object { $documentPath -match [regex]::Escape($_) }))) {
            $userProfilePath = "C:\Users\$username"
            $resolvedPath = Join-Path $userProfilePath $resolvedPath
        }

        return $resolvedPath
    }
    catch {
        return $documentPath  # Return original path if resolution fails
    }
}

# Makes file sizes look pretty
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    if ($ByteSize -eq 0) { return "-" }
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB -and $UnitIndex -lt 5) {
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
        if (-not (Test-Path $documentPath)) {
            throw "File not found: $documentPath"
        }

        $fileInfo = Get-Item $documentPath -ErrorAction Stop
        $acl = Get-Acl $documentPath -ErrorAction Stop
        
        # Calculate SHA256 hash
        $hash = '-'
        try {
            $hash = (Get-FileHash -Path $documentPath -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            #Write-Warning "Failed to calculate hash for $documentPath : $_"
        }

        # Get Zone.Identifier info
        $zoneId = '-'
        $downloadLink = '-'
        $referrerUrl = '-'
        try {
            $adsContent = Get-Content -Path $documentPath -Stream Zone.Identifier -ErrorAction Stop
            if ($adsContent) {
                $zoneIdMatch = $adsContent | Select-String -Pattern '^ZoneId=(\d+)' -ErrorAction SilentlyContinue
                if ($zoneIdMatch) {
                    $zoneId = $zoneIdMatch.Matches.Groups[1].Value
                }
                $hostUrlMatch = $adsContent | Select-String -Pattern '^HostUrl=(.+)' -ErrorAction SilentlyContinue
                if ($hostUrlMatch) {
                    $downloadLink = $hostUrlMatch.Matches.Groups[1].Value
                }
                $referrerUrlMatch = $adsContent | Select-String -Pattern '^ReferrerUrl=(.+)' -ErrorAction SilentlyContinue
                if ($referrerUrlMatch) {
                    $referrerUrl = $referrerUrlMatch.Matches.Groups[1].Value
                }
            }
        } catch {
            #Write-Warning "Failed to read ADS for $documentPath : $_"
        }

        return @{
            SHA256Hash     = $hash
            CreationTime   = if ($fileInfo.CreationTime) { $fileInfo.CreationTime.ToString('o') } else { '-' }
            LastAccessTime = if ($fileInfo.LastAccessTime) { $fileInfo.LastAccessTime.ToString('o') } else { '-' }
            LastWriteTime  = if ($fileInfo.LastWriteTime) { $fileInfo.LastWriteTime.ToString('o') } else { '-' }
            FileSize       = Get-FormattedByteSize -ByteSize $fileInfo.Length
            Owner          = if ([string]::IsNullOrWhiteSpace($acl.Owner)) { '-' } else { $acl.Owner }
            ZoneId         = $zoneId
            DownloadLink   = $downloadLink
            ReferrerUrl    = $referrerUrl
        }
    } catch {
        #Write-Warning "Error processing file $documentPath : $_"
        return @{
            SHA256Hash     = '-'
            CreationTime   = '-'
            LastAccessTime = '-'
            LastWriteTime  = '-'
            FileSize       = '-'
            Owner          = '-'
            ZoneId         = '-'
            DownloadLink   = '-'
            ReferrerUrl    = '-'
        }
    }
}

# This array will hold our registry data
$trustedDocumentsData = @()

# Pattern to match relevant registry data
$registryDataPattern = '^(?<FileName>\s*.+?)\s{2,}(?<RegistryType>REG_BINARY)\s{2,}(?<BinaryData>.+)$'

# Map HKU hive
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null

# Get all user SIDs
$userSIDs = Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' }

foreach ($sid in $userSIDs) {
    $username = try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid.PSChildName)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        $objUser.Value.Split('\')[1]  # Extract just the username part
    } catch {
        "Unknown User (SID: $($sid.PSChildName))"
    }

    # Construct the registry path for Trusted Documents
    $trustRecordsPath = Join-Path $sid.PSPath "Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords"
    
    # Get Trusted Document records for this user
    $trustedDocumentRegistryKeys = Get-ChildItem $trustRecordsPath -ErrorAction SilentlyContinue

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

                # Resolve the full and clean path of the file once, using the username
                $resolvedFilePath = Resolve-DocumentPath -documentPath $FileName -username $username

                # Get file details after path resolution
                $fileInfo = Get-DocumentFileInfo -documentPath $resolvedFilePath

                # Figure out editing and content enabled status from binary data
                $editingEnabled = $false
                $contentEnabled = $false

                if ($BinaryData -match 'FFFFFF7F') {
                    $editingEnabled = $true
                    $contentEnabled = $true
                } elseif ($BinaryData -match '01000000') {
                    $editingEnabled = $true
                    $contentEnabled = $false
                }

                # Add the file info and ADS data to the array
                $trustedDocumentsData += [PSCustomObject]@{
                    Hostname        = $hostname
                    HKCUUser        = "$env:COMPUTERNAME\$username"
                    FileName        = $resolvedFilePath
                    Owner           = $fileInfo.Owner
                    FileSize        = $fileInfo.FileSize
                    EditingEnabled  = $editingEnabled
                    ContentEnabled  = $contentEnabled
                    SHA256Hash      = $fileInfo.SHA256Hash
                    ReferrerUrl     = $fileInfo.ReferrerUrl
                    DownloadLink    = $fileInfo.DownloadLink
                    CreationTime    = $fileInfo.CreationTime
                    LastAccessTime  = $fileInfo.LastAccessTime
                    LastWriteTime   = $fileInfo.LastWriteTime
                    ZoneId          = $fileInfo.ZoneId
                    BinaryData      = $BinaryData
                }
            }
        }
    }
}

# Remove the HKU PSDrive
Remove-PSDrive -Name HKU

# Export everything to a CSV file
$trustedDocumentsData | Export-Csv -Path $outputCsvFilePath -NoTypeInformation

Write-Progress -Activity "Collecting Trusted Documents" -Status "All done!" -PercentComplete 100
