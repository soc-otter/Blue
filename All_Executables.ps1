<#
.SYNOPSIS
Looks for all executables with MZ headers across multiple drives and network mappings.

.DESCRIPTION
This script scans specified drives and network mappings for files with 'MZ' headers, regardless of their extension. It gathers information about each file, including size, owner, digital signature status, hash values, Zone Identifier details (if present), and detailed version information. The script provides options to exclude specific drive letters and paths. Results are exported to a CSV.

.NOTES
Requires PowerShell v5+ and appropriate permissions to access the scan locations.

.AUTHOR
soc-otter

.EXAMPLE
PS> .\All_Executables.ps1 (with hardcoded parameters)

PS> .\All_Executables.ps1 -ExcludeDriveLetters "A", "B" -ExcludeRootPaths "\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2"
#>

param(
    [string[]]$ExcludeDriveLetters,
    [string[]]$ExcludeRootPaths
)

# Default exclusions
$defaultExcludeDriveLetters = @("A", "B")
$defaultExcludeRootPaths = @("\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2")

# Use provided parameters if available, otherwise use defaults
$finalExcludeDriveLetters = if ($ExcludeDriveLetters) { $ExcludeDriveLetters } else { $defaultExcludeDriveLetters }
$finalExcludeRootPaths = if ($ExcludeRootPaths) { $ExcludeRootPaths } else { $defaultExcludeRootPaths }

# Output directory for CSV files
$outputDirectory = 'C:\BlueTeam'
$outputCsvFile = Join-Path $outputDirectory "All_Executables.csv"
$tempCsvFile = Join-Path $outputDirectory "Temp_All_Executables.csv"

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Function to format byte size
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB -and $UnitIndex -lt $SizeUnits.Count - 1) {
        $Size /= 1KB
        $UnitIndex++
    }
    "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
}

# Function to retrieve file owner
function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath -ErrorAction Stop).Owner
    } catch {
        "-"
    }
}

# Function to retrieve Zone.Identifier ADS information
function Get-ZoneIdentifierInfo {
    param ([string]$filePath)
    $zoneId = "-"
    $referrerUrl = "-"
    $hostUrl = "-"

    try {
        $adsContent = Get-Content -Path "$filePath:Zone.Identifier" -ErrorAction Stop
        if ($adsContent -match '^ZoneId=(\d+)') {
            $zoneId = $matches[1]
            switch -Regex ($adsContent) {
                '^ReferrerUrl=(.+)' { $referrerUrl = $matches[1] }
                '^HostUrl=(.+)' { $hostUrl = $matches[1] }
            }
        }
    } catch {}

    [PSCustomObject]@{
        ZoneId = $zoneId
        ReferrerUrl = $referrerUrl
        HostUrl = $hostUrl
    }
}

# Function to add a hyphen for null or empty values
function Add-Hyphen {
    param ($value)
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace($value)) { "-" } else { $value }
}

# Initialize temporary CSV file with headers
$csvHeaders = "CreationTime,Full Path,File Size,File Owner,Status,IsOSBinary,LastWriteTime,LastAccessTime,SignerCertificate,TimeStamperCertificate,SHA256,ZoneId,ReferrerUrl,HostUrl,OriginalFilename,FileDescription,ProductName,Comments,CompanyName,FileVersion,ProductVersion,IsDebug,IsPatched,IsPreRelease,IsPrivateBuild,IsSpecialBuild,Language,LegalCopyright,LegalTrademarks,PrivateBuild,SpecialBuild,FileVersionRaw,ProductVersionRaw,StatusMessage"
Set-Content -Path $tempCsvFile -Value $csvHeaders

# Get drives, excluding specified drive letters and root paths
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.Used -ne $null -and 
    $_.Name -notin $finalExcludeDriveLetters -and
    $_.Root -notin $finalExcludeRootPaths
}

# Initialize variables
$totalDrives = $drives.Count
$currentDriveCount = 0
$totalFilesProcessed = 0
$matchedFilesCount = 0
$batchSize = 100
$batchBuffer = @()
$batchNumber = 1

# Loop through each drive
foreach ($drive in $drives) {
    $currentDriveCount++
    $drivePath = $drive.Root
    $filesProcessedInDrive = 0

    # Update progress for each drive
    $overallPercentComplete = [math]::Min(100, [math]::Round(($currentDriveCount / $totalDrives) * 100, 0))
    Write-Progress -Id 1 -Activity "Processing Drives" -Status "Drive $drivePath ($currentDriveCount of $totalDrives)" -PercentComplete $overallPercentComplete

    # Process files on each drive
    Get-ChildItem -Path $drivePath -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $filesProcessedInDrive++
        $totalFilesProcessed++

        # Update progress for each file processed
        if ($totalFilesProcessed % 100 -eq 0) {
            Write-Progress -Id 2 -Activity "Scanning Files on $drivePath" `
                            -Status "Files Processed: $totalFilesProcessed | Matches: $matchedFilesCount | Batch In Progress: $batchNumber | Files In Memory: $($batchBuffer.Count)" `
                            -PercentComplete -1
        }

        try {
            # Read the first 2 bytes to check for MZ header
            $byteArray = New-Object byte[] 2
            $stream = [System.IO.File]::OpenRead($_.FullName)
            $stream.Read($byteArray, 0, 2) | Out-Null
            $stream.Close()

            if ($byteArray[0] -eq 0x4D -and $byteArray[1] -eq 0x5A) {
                $matchedFilesCount++

                $signature = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
                $fileOwner = Get-FileOwner -FilePath $_.FullName
                $zoneInfo = Get-ZoneIdentifierInfo -filePath $_.FullName
                $sha256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName)

                $fileDetails = [PSCustomObject]@{
                    "CreationTime" = $_.CreationTime
                    "Full Path" = Add-Hyphen $_.FullName
                    "File Size" = Add-Hyphen (Get-FormattedByteSize -ByteSize $_.Length)
                    "File Owner" = Add-Hyphen $fileOwner
                    "Status" = Add-Hyphen $signature.Status
                    "IsOSBinary" = Add-Hyphen $signature.IsOSBinary
                    "LastWriteTime" = Add-Hyphen $_.LastWriteTime
                    "LastAccessTime" = Add-Hyphen $_.LastAccessTime
                    "SignerCertificate" = Add-Hyphen ($signature.SignerCertificate | Select-Object -ExpandProperty Subject -ErrorAction SilentlyContinue)
                    "TimeStamperCertificate" = Add-Hyphen ($signature.TimeStamperCertificate | Select-Object -ExpandProperty Subject -ErrorAction SilentlyContinue)
                    "SHA256" = Add-Hyphen $sha256
                    "ZoneId" = Add-Hyphen $zoneInfo.ZoneId
                    "ReferrerUrl" = Add-Hyphen $zoneInfo.ReferrerUrl
                    "HostUrl" = Add-Hyphen $zoneInfo.HostUrl
                    "OriginalFilename" = Add-Hyphen $versionInfo.OriginalFilename
                    "FileDescription" = Add-Hyphen $versionInfo.FileDescription
                    "ProductName" = Add-Hyphen $versionInfo.ProductName
                    "Comments" = Add-Hyphen $versionInfo.Comments
                    "CompanyName" = Add-Hyphen $versionInfo.CompanyName
                    "FileVersion" = Add-Hyphen $versionInfo.FileVersion
                    "ProductVersion" = Add-Hyphen $versionInfo.ProductVersion
                    "IsDebug" = Add-Hyphen $versionInfo.IsDebug
                    "IsPatched" = Add-Hyphen $versionInfo.IsPatched
                    "IsPreRelease" = Add-Hyphen $versionInfo.IsPreRelease
                    "IsPrivateBuild" = Add-Hyphen $versionInfo.IsPrivateBuild
                    "IsSpecialBuild" = Add-Hyphen $versionInfo.IsSpecialBuild
                    "Language" = Add-Hyphen $versionInfo.Language
                    "LegalCopyright" = Add-Hyphen $versionInfo.LegalCopyright
                    "LegalTrademarks" = Add-Hyphen $versionInfo.LegalTrademarks
                    "PrivateBuild" = Add-Hyphen $versionInfo.PrivateBuild
                    "SpecialBuild" = Add-Hyphen $versionInfo.SpecialBuild
                    "FileVersionRaw" = Add-Hyphen $versionInfo.FileVersionRaw
                    "ProductVersionRaw" = Add-Hyphen $versionInfo.ProductVersionRaw
                    "StatusMessage" = Add-Hyphen $signature.StatusMessage
                }

                $batchBuffer += $fileDetails

                # Write results to CSV in batches
                if ($batchBuffer.Count -ge $batchSize) {
                    $batchBuffer | Export-Csv -Path $tempCsvFile -Append -NoTypeInformation
                    $batchBuffer = @()  # Reset the buffer
                    $batchNumber++
                }
            }
        } catch {}
    }

    Write-Progress -Id 2 -Activity "Scanning Files on $drivePath" -Completed
}

# Export remaining results
if ($batchBuffer.Count -gt 0) {
    $batchBuffer | Export-Csv -Path $tempCsvFile -Append -NoTypeInformation
}

Write-Progress -Id 1 -Activity "Processing Drives" -Completed

# Sort the temporary CSV file by CreationTime and write to the final CSV file
Import-Csv $tempCsvFile | Sort-Object { [DateTime]::Parse($_.CreationTime) } -Descending | 
    Export-Csv -Path $outputCsvFile -NoTypeInformation

# Remove the temporary file
Remove-Item $tempCsvFile
