<#

.SYNOPSIS
Checks the entire file system for files that have been downloaded from the internet.

.DESCRIPTION
This script inspects all files on a Windows system identifying those downloaded from the internet using the Zone.Identifier Alternate Data Streams (ADS). It collects metadata about each file, including size, path, SHA256 hash, owner, creation time, last write time, last access time, and digital signature details. Results are exported to a CSV file in small batches to minimize memory usage and improve performance.

.NOTES
Requires PowerShell v5+ and permissions to access what you are looking to scan.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Internet_Downloaded_Files.ps1

.EXAMPLE
PS> .\Internet_Downloaded_Files.ps1 (using default hardcoded parameters)

PS> .\Internet_Downloaded_Files.ps1 -ExcludeDriveLetters "A", "B" -ExcludeRootPaths "\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2"

#>

param(
    [string[]]$ExcludeDriveLetters,
    [string[]]$ExcludeRootPaths
)

# Default exclusions
$defaultExcludeDriveLetters = @("AAAAA", "BBBBB")
$defaultExcludeRootPaths = @("\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2")

# Use provided parameters if available, otherwise use defaults
$finalExcludeDriveLetters = if ($ExcludeDriveLetters) { $ExcludeDriveLetters } else { $defaultExcludeDriveLetters }
$finalExcludeRootPaths = if ($ExcludeRootPaths) { $ExcludeRootPaths } else { $defaultExcludeRootPaths }

# Output directory and file for CSV
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory 'Internet_Downloaded_Files.csv'

# Ensure output directory exists
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

# Function to get file owner
function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath).Owner
    } catch {
        "-"
    }
}

# Function to get Zone Identifier data
function Get-ZoneIdentifierInfo {
    param ([string]$filePath)
    $zoneId = "-"
    $referrerUrl = "-"
    $hostUrl = "-"

    try {
        $adsContent = Get-Content -Path $filePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($adsContent -match '^ZoneId=3') {
            $zoneId = "3"
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

# Function to retrieve digital signature details
function Get-AuthenticodeSignatureDetails {
    param ([string]$FilePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($null -ne $signature) {
            return [PSCustomObject]@{
                IsOSBinary = if ($signature.IsOSBinary -ne $null) { $signature.IsOSBinary } else { "-" }
                SignerCertificate = if ($signature.SignerCertificate.Subject -ne $null) { $signature.SignerCertificate.Subject } else { "-" }
                TimeStamperCertificate = if ($signature.TimeStamperCertificate.Subject -ne $null) { $signature.TimeStamperCertificate.Subject } else { "-" }
            }
        }
    } catch {}
    return [PSCustomObject]@{
        IsOSBinary = "-"
        SignerCertificate = "-"
        TimeStamperCertificate = "-"
    }
}

# Get drives, excluding specified drive letters and root paths
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.Used -ne $null -and 
    $_.Name -notin $finalExcludeDriveLetters -and
    $_.Root -notin $finalExcludeRootPaths
}

# Calculate the total estimated files based on drive sizes
$totalSizeInTB = [math]::Round(($drives | Measure-Object -Property Used -Sum).Sum / 1TB, 2)
$averageFilesPerTB = 1000000  # Average number of files per TB
$totalFilesEstimate = [math]::Max(1, [math]::Round($totalSizeInTB * $averageFilesPerTB))

# Initialize variables
$totalDrives = $drives.Count
$currentDriveCount = 0
$totalFilesProcessed = 0
$matchedFilesCount = 0
$batchSize = 100
$batchBuffer = @()
$fileWithZoneId3Found = $false
$batchNumber = 1

# Loop through each drive
foreach ($drive in $drives) {
    $currentDriveCount++
    $drivePath = $drive.Root
    $filesProcessedInDrive = 0

    # Update progress for each drive
    $drivePercentComplete = [math]::Min(100, [math]::Round(($currentDriveCount / $totalDrives) * 100, 0))
    Write-Progress -Id 1 -Activity "Processing Drives" -Status "Drive $drivePath ($currentDriveCount of $totalDrives)" -PercentComplete $drivePercentComplete

    # Process files on each drive
    Get-ChildItem -Path $drivePath -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $filesProcessedInDrive++
        $totalFilesProcessed++
        $percentComplete = [math]::Min(100, [math]::Round(($totalFilesProcessed / $totalFilesEstimate) * 100, 2))

        # Update progress for each file processed (every 100 files to reduce overhead)
        if ($totalFilesProcessed % 100 -eq 0) {
            Write-Progress -Id 2 -Activity "Scanning Files on $drivePath" `
                            -Status "Files Processed: $totalFilesProcessed | Matches: $matchedFilesCount | Batch In Progress: $batchNumber | Files In Memory: $($batchBuffer.Count)" `
                            -PercentComplete $percentComplete
        }

        # Check if the file has a Zone.Identifier stream
        if (Get-Item -Path "$($_.FullName):Zone.Identifier" -Force -ErrorAction SilentlyContinue) {
            $zoneInfo = Get-ZoneIdentifierInfo -filePath $_.FullName

            if ($zoneInfo.ZoneId -eq "3") {
                $fileWithZoneId3Found = $true
                $matchedFilesCount++

                $authDetails = Get-AuthenticodeSignatureDetails -FilePath $_.FullName

                $obj = [PSCustomObject]@{
                    "FilePath" = $_.FullName
                    "FileSize" = Get-FormattedByteSize -ByteSize $_.Length
                    "FileSHA256" = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    "FileOwner" = Get-FileOwner -FilePath $_.FullName
                    "FileCreationTime" = $_.CreationTime
                    "FileLastWriteTime" = $_.LastWriteTime
                    "FileLastAccessTime" = $_.LastAccessTime
                    "IsOSBinary" = $authDetails.IsOSBinary
                    "SignerCertificate" = $authDetails.SignerCertificate
                    "TimeStamperCertificate" = $authDetails.TimeStamperCertificate
                    "ZoneId" = $zoneInfo.ZoneId
                    "ReferrerUrl" = $zoneInfo.ReferrerUrl
                    "HostUrl" = $zoneInfo.HostUrl
                }

                $batchBuffer += $obj

                # Write results to CSV in batches
                if ($batchBuffer.Count -ge $batchSize) {
                    if ($null -ne $batchBuffer -and $batchBuffer.Count -gt 0) {
                        try {
                            if (-not (Test-Path $outputFile) -and $fileWithZoneId3Found) {
                                $batchBuffer | Export-Csv -Path $outputFile -NoTypeInformation
                            } else {
                                $batchBuffer | Export-Csv -Path $outputFile -Append -NoTypeInformation
                            }
                            $batchNumber++
                        }
                        catch {
                            #
                        }
                    }
                    $batchBuffer = @()  # Reset the buffer
                }
            }
        }
    }
}

# Export remaining results
if ($null -ne $batchBuffer -and $batchBuffer.Count -gt 0 -and $fileWithZoneId3Found) {
    try {
        $batchBuffer | Export-Csv -Path $outputFile -Append -NoTypeInformation
        $batchNumber++
    }
    catch {
        #
    }
}

Write-Progress -Id 1 -Activity "Processing Drives" -Completed
Write-Progress -Id 2 -Activity "Scanning Files" -Completed

# Sort by newest first
if (Test-Path $outputFile) {
    $sortedData = Import-Csv -Path $outputFile | Sort-Object { [datetime]$_.FileCreationTime } -Descending
    $sortedData | Export-Csv -Path $outputFile -NoTypeInformation -Force
}
