<#
.SYNOPSIS
Scans the file system for high-entropy files based on content using a combination of true and estimated entropy calculations.

.DESCRIPTION
This script analyzes files across the file system and calculates the entropy of their content to identify potentially malicious files. It uses true entropy for smaller files and estimated entropy for larger files. High entropy files may suggest encryption, compression, or other obfuscation techniques used by malicious actors. Results are exported to a CSV.

.NOTES
Requires PowerShell v5+ and permission to access the files being checked.

!!!![WARNING]!!!!
Consider alternative scripts such as `Single_File_Entropy.ps1` if possible. This script takes a long time to run in order to calculate the estimated entropy of each file, even if it is performing random sampling.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Estimated_High_Entropy_Files.ps1

.EXAMPLE
PS> .\Estimated_High_Entropy_Files.ps1 (using default hardcoded parameters)

PS> .\Estimated_High_Entropy_Files.ps1 -IgnoredDrives "A", "B" -ExcludedPaths "\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2"
#>

param(
    [string[]]$IgnoredDrives = @("A", "B"),
    [string[]]$ExcludedPaths = @("\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2"),
    [double]$EntropyLimit = 7.5,
    [int]$ChunkSizeMB = 5,
    [int]$SampleSizeMB = 10
)

# Output and exclusion variables
$outputFolder = 'C:\BlueTeam'
$csvFilePath = Join-Path $outputFolder 'Estimated_High_Entropy_Files.csv'
$tempFilePath = Join-Path $outputFolder 'Temp_Estimated_High_Entropy_Files.csv'
$excludedExtensions = @('.xxxxx', '.yyyyy', '.zzzzz')

if (-not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
}

function Compute-FileEntropyInChunks {
    param([string]$filePath, [int]$chunkSizeBytes)
    
    $entropySum = 0.0
    $totalBytesProcessed = 0
    $chunkBuffer = New-Object byte[] $chunkSizeBytes

    try {
        $fileItem = Get-Item -LiteralPath $filePath -ErrorAction Stop
        $totalChunks = [math]::Ceiling($fileItem.Length / $chunkSizeBytes)
        $chunkIndex = 0

        $fileStream = [System.IO.File]::OpenRead($filePath)
        while ($bytesRead = $fileStream.Read($chunkBuffer, 0, $chunkSizeBytes)) {
            if ($bytesRead -eq 0) { continue }  # Skip empty reads
            $chunkIndex++
            $chunkData = $chunkBuffer[0..($bytesRead - 1)]
            $totalBytesProcessed += $bytesRead
            $entropySum += (Compute-Entropy -byteArray $chunkData) * $bytesRead
            
            Write-Progress -Id 3 -Activity "Processing File: $filePath" `
                -Status "Chunk $chunkIndex of $totalChunks | Size Processed: $(Format-FileSize -sizeInBytes $totalBytesProcessed)" `
                -PercentComplete ([math]::Round(($chunkIndex / $totalChunks) * 100, 2))
        }
        $fileStream.Close()
    } catch {
        return 0.0
    }

    if ($totalBytesProcessed -gt 0) {
        return [math]::Round($entropySum / $totalBytesProcessed, 3)
    } else {
        return 0.0
    }
}

function Compute-EntropyEstimate {
    param([string]$filePath, [int]$sampleSizeBytes)
    
    try {
        $fileItem = Get-Item -LiteralPath $filePath -ErrorAction Stop
        $fileSize = $fileItem.Length
        $sampleBuffer = New-Object byte[] $sampleSizeBytes

        $fileStream = [System.IO.File]::OpenRead($filePath)
        $randomStart = Get-Random -Minimum 0 -Maximum ($fileSize - $sampleSizeBytes)
        $fileStream.Seek($randomStart, [System.IO.SeekOrigin]::Begin) | Out-Null
        $bytesRead = $fileStream.Read($sampleBuffer, 0, $sampleSizeBytes)
        $fileStream.Close()

        if ($bytesRead -gt 0) {
            return Compute-Entropy -byteArray $sampleBuffer[0..($bytesRead - 1)]
        } else {
            return 0.0
        }
    } catch {
        return 0.0
    }
}

function Compute-Entropy {
    param([byte[]]$byteArray)
    $byteLength = $byteArray.Length
    if ($byteLength -eq 0) { return 0.0 }

    $byteFrequencies = @{ }
    foreach ($byte in $byteArray) {
        $byteFrequencies[$byte] = ($byteFrequencies[$byte] + 1)
    }

    $entropyValue = 0.0
    foreach ($frequencyCount in $byteFrequencies.Values) {
        $byteProbability = $frequencyCount / $byteLength
        $entropyValue -= $byteProbability * [math]::Log($byteProbability, 2)
    }
    return [math]::Round($entropyValue, 3)
}

function Format-FileSize {
    param ([double]$sizeInBytes)
    $units = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $index = 0
    while ($sizeInBytes -ge 1KB -and $index -lt $units.Count - 1) {
        $sizeInBytes /= 1KB
        $index++ 
    }
    return "{0:N2} {1}" -f $sizeInBytes, $units[$index]
}

function Get-FileDetails {
    param ([System.IO.FileInfo]$file, [double]$entropy, [string]$method)
    
    $owner = try { (Get-Acl $file.FullName -ErrorAction SilentlyContinue).Owner } catch { "-" }
    $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
    $zoneIdContent = Get-Content -Path $file.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)

    $zoneId = "-"
    $referrerLink = "-"
    $hostAddress = "-"

    if ($null -ne $zoneIdContent) {
        foreach ($line in $zoneIdContent) {
            if ($line -match '^ZoneId=(\d)') {
                $zoneId = $line.Split('=')[1]
            } elseif ($line -match '^ReferrerUrl=(.+)') {
                $referrerLink = $line.Substring($line.IndexOf('=') + 1)
            } elseif ($line -match '^HostUrl=(.+)') {
                $hostAddress = $line.Substring($line.IndexOf('=') + 1)
            }
        }
    }

    return [PSCustomObject]@{
        FilePath = $file.FullName
        EntropyValue = $entropy
        EntropyMethod = $method
        FileSize = Format-FileSize -sizeInBytes $file.Length
        Owner = if ($owner) { $owner } else { "-" }
        FileCreationTime = $file.CreationTime
        FileLastWriteTime = $file.LastWriteTime
        FileLastAccessTime = $file.LastAccessTime
        IsOSBinary = if ($null -ne $signature.IsOSBinary) { $signature.IsOSBinary } else { "-" }
        SignerCertificate = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "-" }
        TimeStamperCertificate = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { "-" }
        ZoneId = $zoneId
        ReferrerLink = $referrerLink
        HostAddress = $hostAddress
        OriginalFilename = if ($versionInfo.OriginalFilename) { $versionInfo.OriginalFilename } else { "-" }
        FileDescription = if ($versionInfo.FileDescription) { $versionInfo.FileDescription } else { "-" }
        ProductName = if ($versionInfo.ProductName) { $versionInfo.ProductName } else { "-" }
        CompanyName = if ($versionInfo.CompanyName) { $versionInfo.CompanyName } else { "-" }
        FileVersion = if ($versionInfo.FileVersion) { $versionInfo.FileVersion } else { "-" }
        ProductVersion = if ($versionInfo.ProductVersion) { $versionInfo.ProductVersion } else { "-" }
        Language = if ($versionInfo.Language) { $versionInfo.Language } else { "-" }
    }
}

$systemDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.Used -ne $null -and 
    $_.Name -notin $IgnoredDrives -and
    $_.Root -notin $ExcludedPaths
}

$totalDriveSpaceInTB = [math]::Round(($systemDrives | Measure-Object -Property Used -Sum).Sum / 1TB, 2)
$estimatedFilesPerTB = 1000000  
$totalEstimatedFiles = [math]::Max(1, [math]::Round($totalDriveSpaceInTB * $estimatedFilesPerTB))

$totalDriveCount = $systemDrives.Count
$currentDriveIndex = 0
$filesProcessed = 0
$highEntropyFileCount = 0
$batchSizeLimit = 5
$bufferForBatch = @()
$batchCounter = 1

foreach ($driveInSystem in $systemDrives) {
    $currentDriveIndex++
    $driveRoot = $driveInSystem.Root
    $filesProcessedInCurrentDrive = 0

    $progressDriveComplete = [math]::Min(100, [math]::Round(($currentDriveIndex / $totalDriveCount) * 100, 0))
    Write-Progress -Id 1 -Activity "Scanning Drives" -Status "Drive: $driveRoot ($currentDriveIndex of $totalDriveCount)" -PercentComplete $progressDriveComplete

    Get-ChildItem -Path $driveRoot -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { 
        $_.Extension -notin $excludedExtensions
    } | ForEach-Object {
        $filesProcessedInCurrentDrive++
        $filesProcessed++
        $fileScanProgress = [math]::Min(100, [math]::Round(($filesProcessed / $totalEstimatedFiles) * 100, 2))

        # Update progress (every 10 files)
        if ($filesProcessed % 10 -eq 0) {
            Write-Progress -Id 2 -Activity "Analyzing Files on $driveRoot" `
                -Status "Files Processed: $filesProcessed | High-Entropy Files: $highEntropyFileCount | Batch: $batchCounter | Files In Memory: $($bufferForBatch.Count)" `
                -PercentComplete $fileScanProgress
        }

        $fileSize = $_.Length
        $sampleSizeBytes = $SampleSizeMB * 1MB
        $chunkSizeBytes = $ChunkSizeMB * 1MB

        if ($fileSize -lt $sampleSizeBytes) {
            $entropy = Compute-FileEntropyInChunks -filePath $_.FullName -chunkSizeBytes $chunkSizeBytes
            $method = "True Entropy"
        } else {
            $entropy = Compute-EntropyEstimate -filePath $_.FullName -sampleSizeBytes $sampleSizeBytes
            $method = "Estimated Entropy"
        }

        if ($entropy -gt $EntropyLimit) {
            $highEntropyFileCount++

            $fileDetails = Get-FileDetails -file $_ -entropy $entropy -method $method

            $bufferForBatch += $fileDetails

            if ($bufferForBatch.Count -ge $batchSizeLimit) {
                $bufferForBatch | Export-Csv -Path $tempFilePath -Append -NoTypeInformation | Out-Null
                $bufferForBatch = @()
                $batchCounter++
            }
        }
    }
}

if ($bufferForBatch.Count -gt 0) {
    $bufferForBatch | Export-Csv -Path $tempFilePath -Append -NoTypeInformation | Out-Null
}

if (Test-Path $tempFilePath) {
    $sortedResults = Import-Csv -Path $tempFilePath | Sort-Object -Property EntropyValue -Descending
    $sortedResults | Export-Csv -Path $csvFilePath -NoTypeInformation -Force | Out-Null
    Remove-Item $tempFilePath -Force | Out-Null
}

Write-Progress -Id 1 -Activity "Processing Complete" -Completed
Write-Progress -Id 2 -Activity "Processing Complete" -Completed
