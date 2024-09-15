<#
.SYNOPSIS
Scans the entire file system for files with the Right-to-Left Override (RTLO) character in their names.

.DESCRIPTION
This script searches all files across specified drives and network mappings for any filenames containing the RTLO character (`U+202E`). This script collects metadata such as size, path, SHA256 hash, owner, creation time, last write time, last access time, digital signature details, and file version information. Results are exported to a CSV.

This can trick users into running malicious programs by masking what they are. As an example, `file[U+202E]fdp.exe` would be shown to the user as `fileexe.pdf`. If you want to test this, you can run this command in PowerShell: `Rename-Item -Path .\test.exe -NewName "test$([char]0x202E)fdp.exe"`. Play around with the extensions, the variations are whatever you want.

.NOTES
Requires PowerShell v5+ and appropriate permissions to access all scan locations.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Files_With_RTLO_Character.ps1

.EXAMPLE
PS> .\Files_With_RTLO_Character.ps1 (using hardcoded parameters as is)

PS> .\Files_With_RTLO_Character.ps1 -ExcludeDriveLetters "A", "B" -ExcludeRootPaths "\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2"
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

# Output directory and file for CSV
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory 'Files_With_RTLO_Character.csv'

# Ensure output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Function to check for the RTLO character in file names
function Contains-RTLOCharacter {
    param ([string]$fileName)
    return $fileName -match [char]0x202E
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
        $owner = (Get-Acl $FilePath).Owner
        if ([string]::IsNullOrEmpty($owner)) { "-" } else { $owner }
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
                '^HostUrl=(.+)'     { $hostUrl = $matches[1] }
            }
        }
    } catch {}

    [PSCustomObject]@{
        ZoneId      = if ([string]::IsNullOrEmpty($zoneId)) { "-" } else { $zoneId }
        ReferrerUrl = if ([string]::IsNullOrEmpty($referrerUrl)) { "-" } else { $referrerUrl }
        HostUrl     = if ([string]::IsNullOrEmpty($hostUrl)) { "-" } else { $hostUrl }
    }
}

# Function to retrieve signatures info
function Get-AuthenticodeSignatureDetails {
    param ([string]$FilePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($null -ne $signature) {
            return [PSCustomObject]@{
                IsOSBinary             = if ($signature.IsOSBinary -ne $null) { $signature.IsOSBinary } else { "-" }
                SignerCertificate      = if ($signature.SignerCertificate -and $signature.SignerCertificate.Subject) { $signature.SignerCertificate.Subject } else { "-" }
                TimeStamperCertificate = if ($signature.TimeStamperCertificate -and $signature.TimeStamperCertificate.Subject) { $signature.TimeStamperCertificate.Subject } else { "-" }
            }
        }
    } catch {}
    return [PSCustomObject]@{
        IsOSBinary             = "-"
        SignerCertificate      = "-"
        TimeStamperCertificate = "-"
    }
}

# Function to get file version information
function Get-FileVersionInfo {
    param ([string]$filePath)
    try {
        $fileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath)
        return [PSCustomObject]@{
            OriginalFilename  = if ([string]::IsNullOrEmpty($fileVersionInfo.OriginalFilename))  { "-" } else { $fileVersionInfo.OriginalFilename }
            FileDescription   = if ([string]::IsNullOrEmpty($fileVersionInfo.FileDescription))   { "-" } else { $fileVersionInfo.FileDescription }
            ProductName       = if ([string]::IsNullOrEmpty($fileVersionInfo.ProductName))       { "-" } else { $fileVersionInfo.ProductName }
            Comments          = if ([string]::IsNullOrEmpty($fileVersionInfo.Comments))          { "-" } else { $fileVersionInfo.Comments }
            CompanyName       = if ([string]::IsNullOrEmpty($fileVersionInfo.CompanyName))       { "-" } else { $fileVersionInfo.CompanyName }
            FileName          = if ([string]::IsNullOrEmpty($fileVersionInfo.FileName))          { "-" } else { $fileVersionInfo.FileName }
            FileVersion       = if ([string]::IsNullOrEmpty($fileVersionInfo.FileVersion))       { "-" } else { $fileVersionInfo.FileVersion }
            ProductVersion    = if ([string]::IsNullOrEmpty($fileVersionInfo.ProductVersion))    { "-" } else { $fileVersionInfo.ProductVersion }
            IsDebug           = if ($fileVersionInfo.IsDebug -ne $null)                          { $fileVersionInfo.IsDebug } else { "-" }
            IsPatched         = if ($fileVersionInfo.IsPatched -ne $null)                        { $fileVersionInfo.IsPatched } else { "-" }
            IsPreRelease      = if ($fileVersionInfo.IsPreRelease -ne $null)                     { $fileVersionInfo.IsPreRelease } else { "-" }
            IsPrivateBuild    = if ($fileVersionInfo.IsPrivateBuild -ne $null)                   { $fileVersionInfo.IsPrivateBuild } else { "-" }
            IsSpecialBuild    = if ($fileVersionInfo.IsSpecialBuild -ne $null)                   { $fileVersionInfo.IsSpecialBuild } else { "-" }
            Language          = if ([string]::IsNullOrEmpty($fileVersionInfo.Language))          { "-" } else { $fileVersionInfo.Language }
            LegalCopyright    = if ([string]::IsNullOrEmpty($fileVersionInfo.LegalCopyright))    { "-" } else { $fileVersionInfo.LegalCopyright }
            LegalTrademarks   = if ([string]::IsNullOrEmpty($fileVersionInfo.LegalTrademarks))   { "-" } else { $fileVersionInfo.LegalTrademarks }
            PrivateBuild      = if ([string]::IsNullOrEmpty($fileVersionInfo.PrivateBuild))      { "-" } else { $fileVersionInfo.PrivateBuild }
            SpecialBuild      = if ([string]::IsNullOrEmpty($fileVersionInfo.SpecialBuild))      { "-" } else { $fileVersionInfo.SpecialBuild }
            FileVersionRaw    = if ([string]::IsNullOrEmpty($fileVersionInfo.FileVersionRaw))    { "-" } else { $fileVersionInfo.FileVersionRaw }
            ProductVersionRaw = if ([string]::IsNullOrEmpty($fileVersionInfo.ProductVersionRaw)) { "-" } else { $fileVersionInfo.ProductVersionRaw }
        }
    } catch {}
    return [PSCustomObject]@{
        OriginalFilename  = "-"
        FileDescription   = "-"
        ProductName       = "-"
        Comments          = "-"
        CompanyName       = "-"
        FileName          = "-"
        FileVersion       = "-"
        ProductVersion    = "-"
        IsDebug           = "-"
        IsPatched         = "-"
        IsPreRelease      = "-"
        IsPrivateBuild    = "-"
        IsSpecialBuild    = "-"
        Language          = "-"
        LegalCopyright    = "-"
        LegalTrademarks   = "-"
        PrivateBuild      = "-"
        SpecialBuild      = "-"
        FileVersionRaw    = "-"
        ProductVersionRaw = "-"
    }
}

# Function to simulate how the file name appears to the user
function Get-DisplayedFilePath {
    param ([string]$fullFilePath)
    
    $directory = [System.IO.Path]::GetDirectoryName($fullFilePath)
    $fileName = [System.IO.Path]::GetFileName($fullFilePath)
    
    if ($fileName.Contains([char]0x202E)) {
        # Split at the RTLO character
        $parts = $fileName -split [char]0x202E, 2
        $beforeRTLO = $parts[0]
        $afterRTLO = $parts[1]
        # Reverse the text after the RTLO character
        $charArray = $afterRTLO.ToCharArray()
        [Array]::Reverse($charArray)
        $reversed = -join $charArray
        # Combine the parts to get the displayed file name
        $displayedFileName = $beforeRTLO + $reversed
    } else {
        $displayedFileName = $fileName
    }
    
    if ($directory) {
        return [System.IO.Path]::Combine($directory, $displayedFileName)
    } else {
        return $displayedFileName
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

        # Check if the file name contains the RTLO character
        if (Contains-RTLOCharacter -fileName $_.Name) {
            $matchedFilesCount++

            $authDetails = Get-AuthenticodeSignatureDetails -FilePath $_.FullName
            $zoneInfo = Get-ZoneIdentifierInfo -filePath $_.FullName
            $fileVersionInfo = Get-FileVersionInfo -filePath $_.FullName

            $obj = [PSCustomObject]@{
                "FilePath"                = $_.FullName
                "DisplayedFilePath"       = Get-DisplayedFilePath -fullFilePath $_.FullName
                "FileSize"                = Get-FormattedByteSize -ByteSize $_.Length
                "FileSHA256"              = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                "FileOwner"               = Get-FileOwner -FilePath $_.FullName
                "FileCreationTime"        = $_.CreationTime
                "FileLastWriteTime"       = $_.LastWriteTime
                "FileLastAccessTime"      = $_.LastAccessTime
                "IsOSBinary"              = $authDetails.IsOSBinary
                "SignerCertificate"       = $authDetails.SignerCertificate
                "TimeStamperCertificate"  = $authDetails.TimeStamperCertificate
                "ZoneId"                  = $zoneInfo.ZoneId
                "ReferrerUrl"             = $zoneInfo.ReferrerUrl
                "HostUrl"                 = $zoneInfo.HostUrl
                "OriginalFilename"        = $fileVersionInfo.OriginalFilename
                "FileDescription"         = $fileVersionInfo.FileDescription
                "ProductName"             = $fileVersionInfo.ProductName
                "Comments"                = $fileVersionInfo.Comments
                "CompanyName"             = $fileVersionInfo.CompanyName
                "FileName"                = $fileVersionInfo.FileName
                "FileVersion"             = $fileVersionInfo.FileVersion
                "ProductVersion"          = $fileVersionInfo.ProductVersion
                "IsDebug"                 = $fileVersionInfo.IsDebug
                "IsPatched"               = $fileVersionInfo.IsPatched
                "IsPreRelease"            = $fileVersionInfo.IsPreRelease
                "IsPrivateBuild"          = $fileVersionInfo.IsPrivateBuild
                "IsSpecialBuild"          = $fileVersionInfo.IsSpecialBuild
                "Language"                = $fileVersionInfo.Language
                "LegalCopyright"          = $fileVersionInfo.LegalCopyright
                "LegalTrademarks"         = $fileVersionInfo.LegalTrademarks
                "PrivateBuild"            = $fileVersionInfo.PrivateBuild
                "SpecialBuild"            = $fileVersionInfo.SpecialBuild
                "FileVersionRaw"          = $fileVersionInfo.FileVersionRaw
                "ProductVersionRaw"       = $fileVersionInfo.ProductVersionRaw
            }

            # Ensure that any null or empty values are replaced with "-"
            foreach ($property in $obj.PSObject.Properties) {
                if ([string]::IsNullOrEmpty($property.Value)) {
                    $obj.$($property.Name) = "-"
                }
            }

            $batchBuffer += $obj

            # Write results to CSV in batches
            if ($batchBuffer.Count -ge $batchSize) {
                $batchBuffer | Export-Csv -Path $outputFile -Append -NoTypeInformation
                $batchBuffer = @()  # Reset the buffer
                $batchNumber++
            }
        }
    }

    Write-Progress -Id 2 -Activity "Scanning Files on $drivePath" -Completed
}

# Export remaining results
if ($batchBuffer.Count -gt 0) {
    $batchBuffer | Export-Csv -Path $outputFile -Append -NoTypeInformation
    $batchNumber++
}

Write-Progress -Id 1 -Activity "Processing Drives" -Completed

# Sort by newest first
if (Test-Path $outputFile) {
    $sortedData = Import-Csv -Path $outputFile | Sort-Object { [datetime]$_.FileCreationTime } -Descending
    $sortedData | Export-Csv -Path $outputFile -NoTypeInformation -Force
}
