<#
.SYNOPSIS
Scans the file system for file names with high entropy.

.DESCRIPTION
This analyzes file names looking for those with high-entropy character combinations. High-entropy file names can suggest obfuscation or malicious intent. Results are exported to a CSV.

.NOTES
Requires PowerShell v5+ and administrative privileges for full access to system files.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/High_Entropy_File_Names.ps1

.EXAMPLE
PS> .\High_Entropy_File_Names.ps1 (using default hardcoded parameters)

PS> .\High_Entropy_File_Names.ps1 -ExcludeDriveLetters "A", "B" -ExcludeRootPaths "\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2"
#>

param(
    [string[]]$IgnoredDrives = @("A", "B"),
    [string[]]$ExcludedPaths = @("\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2"),
    [double]$EntropyLimit = 5.0
)

# Output directory and file for CSV
$outputFolder = 'C:\BlueTeam'
$csvFilePath = Join-Path $outputFolder 'High_Entropy_File_Names.csv'
$tempFilePath = Join-Path $outputFolder 'Temp_High_Entropy_File_Names.csv'

# Ensure output directory exists
if (-not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
}

# Function to calculate entropy for a given string (file name)
function Compute-FileNameEntropy {
    param([string]$nameString)
    $stringLength = $nameString.Length
    if ($stringLength -eq 0) { return 0 }

    $charFrequencies = @{}
    foreach ($character in $nameString.ToCharArray()) {
        $charFrequencies[$character] = ($charFrequencies[$character] + 1)
    }

    $entropyValue = 0.0
    foreach ($frequencyCount in $charFrequencies.Values) {
        $charProbability = $frequencyCount / $stringLength
        $entropyValue -= $charProbability * [math]::Log($charProbability, 2)
    }
    return [math]::Round($entropyValue, 3)
}

# Function to format file size
function Format-FileSize {
    param ([double]$sizeInBytes)
    $unitsArray = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $unitPosition = 0
    $formattedSize = [math]::Round($sizeInBytes, 2)
    while ($formattedSize -ge 1KB -and $unitPosition -lt $unitsArray.Count - 1) {
        $formattedSize /= 1KB
        $unitPosition++
    }
    return "{0:N2} {1}" -f $formattedSize, $unitsArray[$unitPosition]
}

# Function to retrieve the file owner
function Get-OwnerOfFile {
    param ([string]$pathToFile)
    try {
        $fileOwnerName = (Get-Acl $pathToFile -ErrorAction SilentlyContinue).Owner
        if ($null -eq $fileOwnerName -or [string]::IsNullOrEmpty($fileOwnerName)) { "-" } else { $fileOwnerName }
    } catch {
        "-"
    }
}

# Function to get Zone Identifier data from file Alternate Data Streams (ADS)
function Retrieve-ZoneIdentifierData {
    param ([string]$filePathInput)
    $zoneIdentifier = "-"
    $referrerLink = "-"
    $hostAddress = "-"

    try {
        $zoneData = Get-Content -Path $filePathInput -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($zoneData -match '^ZoneId=3') {
            $zoneIdentifier = "3"
            switch -Regex ($zoneData) {
                '^ReferrerUrl=(.+)' { $referrerLink = $matches[1] }
                '^HostUrl=(.+)' { $hostAddress = $matches[1] }
            }
        }
    } catch {}

    [PSCustomObject]@{
        ZoneId      = $zoneIdentifier
        ReferrerUrl = if ($referrerLink) { $referrerLink } else { "-" }
        HostUrl     = if ($hostAddress) { $hostAddress } else { "-" }
    }
}

# Function to retrieve digital signature details of a file
function Get-DigitalSignatureInfo {
    param ([string]$pathToFile)
    try {
        $fileSignature = Get-AuthenticodeSignature -FilePath $pathToFile -ErrorAction SilentlyContinue
        if ($fileSignature -ne $null) {
            return [PSCustomObject]@{
                IsSystemFile          = if ($fileSignature.IsOSBinary -ne $null) { $fileSignature.IsOSBinary } else { "-" }
                SignerIdentity        = if ($fileSignature.SignerCertificate.Subject -ne $null) { $fileSignature.SignerCertificate.Subject } else { "-" }
                TimeStampCert         = if ($fileSignature.TimeStamperCertificate.Subject -ne $null) { $fileSignature.TimeStamperCertificate.Subject } else { "-" }
            }
        }
    } catch {}
    return [PSCustomObject]@{
        IsSystemFile          = "-"
        SignerIdentity        = "-"
        TimeStampCert         = "-"
    }
}

# Exclude specified drive letters and root paths from the scan
$systemDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.Used -ne $null -and 
    $_.Name -notin $IgnoredDrives -and
    $_.Root -notin $ExcludedPaths
}

# Estimate the total number of files based on drive sizes
$totalDriveSpaceInTB = [math]::Round(($systemDrives | Measure-Object -Property Used -Sum).Sum / 1TB, 2)
$estimatedFilesPerTB = 1000000  # Assumed average number of files per TB
$totalEstimatedFiles = [math]::Max(1, [math]::Round($totalDriveSpaceInTB * $estimatedFilesPerTB))

# Start counters and batch processing
$totalDriveCount = $systemDrives.Count
$currentDriveIndex = 0
$filesProcessed = 0
$highEntropyFileCount = 0
$batchSizeLimit = 100
$bufferForBatch = @()
$batchCounter = 1

# Scan each drive and process files
foreach ($driveInSystem in $systemDrives) {
    $currentDriveIndex++
    $driveRoot = $driveInSystem.Root
    $filesProcessedInCurrentDrive = 0

    # Display progress for each drive being processed
    $progressDriveComplete = [math]::Min(100, [math]::Round(($currentDriveIndex / $totalDriveCount) * 100, 0))
    Write-Progress -Id 1 -Activity "Scanning Drives" -Status "Drive: $driveRoot ($currentDriveIndex of $totalDriveCount)" -PercentComplete $progressDriveComplete

    # Retrieve all files in the drive
    Get-ChildItem -Path $driveRoot -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $filesProcessedInCurrentDrive++
        $filesProcessed++
        $fileScanProgress = [math]::Min(100, [math]::Round(($filesProcessed / $totalEstimatedFiles) * 100, 2))

        # Update progress every 100 files
        if ($filesProcessed % 100 -eq 0) {
            Write-Progress -Id 2 -Activity "Analyzing Files on $driveRoot" `
                            -Status "Files Processed: $filesProcessed | High-Entropy File Names: $highEntropyFileCount | Batch: $batchCounter | Files In Memory: $($bufferForBatch.Count)" `
                            -PercentComplete $fileScanProgress
        }

        $currentFile = $_.Name
        $calculatedEntropy = Compute-FileNameEntropy -nameString $currentFile

        if ($calculatedEntropy -gt $EntropyLimit) {
            $highEntropyFileCount++
            $digitalSignature = Get-DigitalSignatureInfo -pathToFile $_.FullName
            $zoneIdentifierDetails = Retrieve-ZoneIdentifierData -filePathInput $_.FullName
            $versionInformation = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName)

            $fileDetails = [PSCustomObject]@{
                FilePath              = if ([string]::IsNullOrEmpty($_.FullName)) { "-" } else { $_.FullName }
                FileName              = if ([string]::IsNullOrEmpty($currentFile)) { "-" } else { $currentFile }
                EntropyValue          = if ([string]::IsNullOrEmpty($calculatedEntropy)) { "-" } else { $calculatedEntropy }
                FileSize              = if ([string]::IsNullOrEmpty($_.Length)) { "-" } else { Format-FileSize -sizeInBytes $_.Length }
                Owner                 = if ([string]::IsNullOrEmpty((Get-OwnerOfFile -pathToFile $_.FullName))) { "-" } else { Get-OwnerOfFile -pathToFile $_.FullName }
                FileCreationTime      = if ([string]::IsNullOrEmpty($_.CreationTime)) { "-" } else { $_.CreationTime }
                FileLastWriteTime     = if ([string]::IsNullOrEmpty($_.LastWriteTime)) { "-" } else { $_.LastWriteTime }
                FileLastAccessTime    = if ([string]::IsNullOrEmpty($_.LastAccessTime)) { "-" } else { $_.LastAccessTime }
                SystemFileStatus      = if ([string]::IsNullOrEmpty($digitalSignature.IsSystemFile)) { "-" } else { $digitalSignature.IsSystemFile }
                FileSigner            = if ([string]::IsNullOrEmpty($digitalSignature.SignerIdentity)) { "-" } else { $digitalSignature.SignerIdentity }
                TimeStampSigner       = if ([string]::IsNullOrEmpty($digitalSignature.TimeStampCert)) { "-" } else { $digitalSignature.TimeStampCert }
                ZoneId               = if ([string]::IsNullOrEmpty($zoneIdentifierDetails.ZoneId)) { "-" } else { $zoneIdentifierDetails.ZoneId }
                ReferrerLink          = if ([string]::IsNullOrEmpty($zoneIdentifierDetails.ReferrerUrl)) { "-" } else { $zoneIdentifierDetails.ReferrerUrl }
                HostAddress           = if ([string]::IsNullOrEmpty($zoneIdentifierDetails.HostUrl)) { "-" } else { $zoneIdentifierDetails.HostUrl }
                OriginalFilename      = if ([string]::IsNullOrEmpty($versionInformation.OriginalFilename)) { "-" } else { $versionInformation.OriginalFilename }
                FileDescription       = if ([string]::IsNullOrEmpty($versionInformation.FileDescription)) { "-" } else { $versionInformation.FileDescription }
                ProductName           = if ([string]::IsNullOrEmpty($versionInformation.ProductName)) { "-" } else { $versionInformation.ProductName }
                CompanyName           = if ([string]::IsNullOrEmpty($versionInformation.CompanyName)) { "-" } else { $versionInformation.CompanyName }
                FileVersion           = if ([string]::IsNullOrEmpty($versionInformation.FileVersion)) { "-" } else { $versionInformation.FileVersion }
                ProductVersion        = if ([string]::IsNullOrEmpty($versionInformation.ProductVersion)) { "-" } else { $versionInformation.ProductVersion }
                Language              = if ([string]::IsNullOrEmpty($versionInformation.Language)) { "-" } else { $versionInformation.Language }
            }

            # Add file details to the batch buffer
            $bufferForBatch += $fileDetails

            # Write results to a temporary CSV in batches
            if ($bufferForBatch.Count -ge $batchSizeLimit) {
                $bufferForBatch | Export-Csv -Path $tempFilePath -Append -NoTypeInformation
                $bufferForBatch = @()  # Reset the buffer
                $batchCounter++
            }
        }
    }
}

# Export remaining file details if any
if ($bufferForBatch.Count -gt 0) {
    $bufferForBatch | Export-Csv -Path $tempFilePath -Append -NoTypeInformation
}

# Sort by highest entropy value
if (Test-Path $tempFilePath) {
    $sortedResults = Import-Csv -Path $tempFilePath | Sort-Object -Property EntropyValue -Descending
    $sortedResults | Export-Csv -Path $csvFilePath -NoTypeInformation -Force
    Remove-Item $tempFilePath -Force
}

Write-Progress -Id 1 -Activity "Processing Complete" -Completed
