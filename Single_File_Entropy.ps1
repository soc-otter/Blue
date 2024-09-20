<#
.SYNOPSIS
Calculates the entropy of a specified file and saves the results to a CSV and a quick summary output to the terminal.

.DESCRIPTION
This script calculates the entropy of a single file's content to help identify potentially malicious files. It offers two methods: true entropy calculation and quick estimation using random sampling. The results are displayed in the terminal and exported to a CSV file. By default, it uses the estimated entropy method for faster results on large files, but automatically switches to true entropy for small files.

.NOTES
Requires PowerShell v5+ and permission to access the file being checked.

.PARAMETER EstimatedEntropy
Switch to use random sampling for a quick entropy estimate. This is faster but less accurate for large files. This is the default method for large files if neither EstimatedEntropy nor TrueEntropy is specified.

.PARAMETER TrueEntropy
Switch to calculate true entropy of the entire file. This can be time-consuming for large files but is always used for small files.

.PARAMETER File
The path to the file to analyze. Defaults to notepad.exe if not specified.

.PARAMETER ChunkSizeMB
The size of chunks to process for true entropy calculation. Default is 5 MB, if not specified.

.PARAMETER SampleSizeMB
The size of the random sample to use when EstimatedEntropy is specified. Default is 10 MB, if not specified.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Single_File_Entropy.ps1

.EXAMPLE
PS> .\Single_File_Entropy.ps1 -File "C:\example\largefile.bin"

PS> .\Single_File_Entropy.ps1 -EstimatedEntropy -File "C:\path\to\largefile.bin" -SampleSizeMB 20

PS> .\Single_File_Entropy.ps1 -TrueEntropy -File "C:\path\to\smallfile.txt"

PS> .\Single_File_Entropy.ps1 -EstimatedEntropy -File "C:\path\to\largefile.bin"
#>

param(
    [switch]$EstimatedEntropy,
    [switch]$TrueEntropy,
    [string]$File = "C:\Windows\System32\notepad.exe",
    [int]$ChunkSizeMB = 5,
    [int]$SampleSizeMB = 10
)

# Output variables
$outputFolder = 'C:\BlueTeam'
$csvFilePath = Join-Path $outputFolder 'Single_File_Entropy.csv'

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
            if ($bytesRead -eq 0) { continue }
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
        Write-Warning "Skipped file ${filePath}: $($_.Exception.Message)"
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
        
        if ($fileSize -le $sampleSizeBytes) {
            # If file is smaller than or equal to sample size, process the entire file
            return Compute-Entropy -byteArray ([System.IO.File]::ReadAllBytes($filePath))
        }

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
        Write-Warning "Error sampling file ${filePath}: $($_.Exception.Message)"
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
        Method = $method
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

function Format-Output {
    param (
        [string]$FilePath,
        [double]$Entropy,
        [string]$Method,
        [string]$FileSize
    )

    $width = 80
    $separator = "-" * $width

    Write-Host $separator
    Write-Host "File Entropy Analysis Result" -ForegroundColor Cyan
    Write-Host $separator
    Write-Host "File:".PadRight(15) $FilePath
    Write-Host "Size:".PadRight(15) $FileSize
    Write-Host "Method:".PadRight(15) $Method
    Write-Host "Entropy:".PadRight(15) ("{0:F3}" -f $Entropy)
    Write-Host $separator
    Write-Host "Results saved to: $csvFilePath" -ForegroundColor Yellow
    Write-Host $separator
}

# Process the specified file
Write-Host "Analyzing file: $File" -ForegroundColor Cyan

$fileInfo = Get-Item -LiteralPath $File
$fileSize = $fileInfo.Length
$sampleSizeBytes = $SampleSizeMB * 1MB
$chunkSizeBytes = $ChunkSizeMB * 1MB

if ($TrueEntropy -and $EstimatedEntropy) {
    Write-Warning "Both TrueEntropy and EstimatedEntropy specified. Defaulting to TrueEntropy."
    $EstimatedEntropy = $false
}

if ($fileSize -lt $sampleSizeBytes -or $fileSize -lt $chunkSizeBytes -or $TrueEntropy) {
    $method = "True Entropy"
    $entropy = Compute-Entropy -byteArray ([System.IO.File]::ReadAllBytes($File))
} elseif ($EstimatedEntropy -or (-not $TrueEntropy)) {
    $method = "Estimated Entropy"
    $entropy = Compute-EntropyEstimate -filePath $File -sampleSizeBytes $sampleSizeBytes
} else {
    $method = "True Entropy"
    $entropy = Compute-FileEntropyInChunks -filePath $File -chunkSizeBytes $chunkSizeBytes
}

if ($entropy -gt 0) {
    $fileSizeFormatted = Format-FileSize -sizeInBytes $fileSize
    Format-Output -FilePath $File -Entropy $entropy -Method $method -FileSize $fileSizeFormatted
    
    $fileDetails = Get-FileDetails -file $fileInfo -entropy $entropy -method $method
    $fileDetails | Export-Csv -Path $csvFilePath -NoTypeInformation -Append -Force
} else {
    Write-Warning "The file could not be processed or has zero entropy."
}
