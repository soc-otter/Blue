<#

.SYNOPSIS
Checks for alternate data streams across all files.

.DESCRIPTION
This script checks all files for alternate data streams (ADS). It collects detailed metadata about each file and its ADS. Results get written to a CSV file.

.NOTES
Requires PowerShell v5+ and admin rights.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Alternate_Data_Streams.ps1

.EXAMPLE
.\Alternate_Data_Streams.ps1

#>

# Ensure admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    throw "Admin privileges required."
}

$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory 'Alternate_Data_Streams.csv'
$batchSize = 100

# Ensure output directory exists
New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

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

function Get-FileHash {
    param ([string]$FilePath)
    try {
        (Microsoft.PowerShell.Utility\Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { "-" }
}

function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath -ErrorAction Stop).Owner
    } catch { "-" }
}

function Get-SignatureInfo {
    param ([string]$FilePath)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        [PSCustomObject]@{
            Status = $sig.Status
            SignerCertificate = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "-" }
            TimeStamperCertificate = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { "-" }
            IsOSBinary = if ($null -ne $sig.IsOSBinary) { $sig.IsOSBinary.ToString() } else { "-" }
        }
    } catch {
        [PSCustomObject]@{
            Status = "Error"
            SignerCertificate = "-"
            TimeStamperCertificate = "-"
            IsOSBinary = "-"
        }
    }
}

function Is-FilePath {
    param ([string]$Path)
    $Path -match '^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$'
}

function Get-ADSReferencedPathHash {
    param ([string]$StreamContent)
    $streamContentTrimmed = $StreamContent.Trim()

    if (Is-FilePath $streamContentTrimmed) {
        $adsHash = Get-FileHash $streamContentTrimmed
        return [PSCustomObject]@{
            Path = $streamContentTrimmed
            Hash = $adsHash
        }
    } else {
        return [PSCustomObject]@{
            Path = "-"
            Hash = "-"
        }
    }
}

function Check-FileExists {
    param ([string]$FilePath)
    return Test-Path -Path $FilePath
}

function Process-Drive {
    param (
        [string]$DriveLetter,
        [string]$OutputFile,
        [int]$BatchSize,
        [int]$CurrentDriveCount,
        [int]$TotalDrives,
        [long]$TotalFilesEstimate
    )

    $batchBuffer = New-Object System.Collections.ArrayList
    $filesWithADS = 0
    $filesProcessed = 0
    $batchNumber = 1
    $totalFilesProcessed = 0
    $accessDeniedCount = 0

    Get-ChildItem -Path $DriveLetter -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $filesProcessed++
        $totalFilesProcessed++
        $percentComplete = [math]::Min(100, [math]::Round(($totalFilesProcessed / $TotalFilesEstimate) * 100, 2))

        if ($totalFilesProcessed % 100 -eq 0) {
            $drivePercentComplete = [math]::Min(100, [math]::Round(($CurrentDriveCount / $TotalDrives) * 100, 0))
            Write-Progress -Id 1 -Activity "Processing Drives" -Status "Drive $DriveLetter ($CurrentDriveCount of $TotalDrives)" -PercentComplete $drivePercentComplete
            Write-Progress -Id 2 -Activity "Scanning Files on $DriveLetter" `
                            -Status "Files Processed: $totalFilesProcessed | Matches: $filesWithADS | Batch In Progress: $batchNumber | Access Denied: $accessDeniedCount | Files In Memory: $($batchBuffer.Count)" `
                            -PercentComplete $percentComplete
        }

        try {
            $streams = Get-Item -Path $_.FullName -Stream * -ErrorAction Stop | Where-Object { $_.Stream -ne ':$DATA' }
            
            if ($streams) {
                $filesWithADS++
                $fileInfo = [PSCustomObject]@{
                    FilePath = $_.FullName
                    FileSize = Get-FormattedByteSize $_.Length
                    FileSHA256 = Get-FileHash $_.FullName
                    FileOwner = Get-FileOwner $_.FullName
                    FileExtension = $_.Extension
                    CreationTime = $_.CreationTime.ToString('o')
                    LastWriteTime = $_.LastWriteTime.ToString('o')
                    LastAccessTime = $_.LastAccessTime.ToString('o')
                }

                $sigInfo = Get-SignatureInfo $_.FullName

                foreach ($stream in $streams) {
                    $streamContent = Get-Content -Path $_.FullName -Stream $stream.Stream -Raw -ErrorAction SilentlyContinue
                    $adsReferencedPathHash = Get-ADSReferencedPathHash $streamContent
                    $fileExists = if (Is-FilePath $streamContent) { Check-FileExists $streamContent } else { $false }

                    [void]$batchBuffer.Add([PSCustomObject]@{
                        FilePath = $fileInfo.FilePath
                        FileSize = $fileInfo.FileSize
                        FileSHA256 = $fileInfo.FileSHA256
                        FileOwner = $fileInfo.FileOwner
                        FileExtension = $fileInfo.FileExtension
                        CreationTime = $fileInfo.CreationTime
                        LastWriteTime = $fileInfo.LastWriteTime
                        LastAccessTime = $fileInfo.LastAccessTime
                        SignatureStatus = $sigInfo.Status
                        SignerCertificate = $sigInfo.SignerCertificate
                        TimeStamperCertificate = $sigInfo.TimeStamperCertificate
                        IsOSBinary = $sigInfo.IsOSBinary
                        StreamName = $stream.Stream
                        StreamSize = Get-FormattedByteSize $stream.Length
                        StreamContent = if ($streamContent) { $streamContent } else { "-" }
                        ADSReferencedPath = $adsReferencedPathHash.Path
                        ADSReferencedPathExists = $fileExists
                        ADSReferencedPathHash = $adsReferencedPathHash.Hash
                    })
                }

                if ($batchBuffer.Count -ge $BatchSize) {
                    $batchBuffer | Export-Csv -Path $OutputFile -NoTypeInformation -Append
                    $batchBuffer.Clear()
                    $batchNumber++
                }
            }
        }
        catch [System.UnauthorizedAccessException] {
            $accessDeniedCount++
        }
        catch {
            #
        }
    }

    if ($batchBuffer.Count -gt 0) {
        $batchBuffer | Export-Csv -Path $OutputFile -NoTypeInformation -Append
    }

    [PSCustomObject]@{
        DriveLetter = $DriveLetter
        FilesProcessed = $filesProcessed
        FilesWithADS = $filesWithADS
        AccessDeniedCount = $accessDeniedCount
    }
}

# Get drives and calculate total estimated files
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $null -ne $_.Used }
$totalDrives = @($drives).Count
$currentDriveCount = 0

$totalSizeInTB = [math]::Round(($drives | Measure-Object -Property Used -Sum).Sum / 1TB, 2)
$averageFilesPerTB = 1000000  # Average number of files per TB
$totalFilesEstimate = [math]::Max(1, [math]::Round($totalSizeInTB * $averageFilesPerTB))

$results = foreach ($drive in $drives) {
    $currentDriveCount++
    Process-Drive -DriveLetter $drive.Root -OutputFile $outputFile -BatchSize $batchSize -CurrentDriveCount $currentDriveCount -TotalDrives $totalDrives -TotalFilesEstimate $totalFilesEstimate
}

Write-Progress -Id 1 -Activity "Processing Drives" -Completed
Write-Progress -Id 2 -Activity "Scanning Files" -Completed
