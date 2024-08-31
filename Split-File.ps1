<#
.SYNOPSIS
Splits a large file into smaller pieces.

.DESCRIPTION
This script divides a large file into smaller chunks of a specified size in gigabytes. It is useful for managing and transferring large files by breaking them down into manageable parts.

.EXAMPLE
[!] It is recommended to first compress files before splitting for best results (i.e. - zip).
PS> .\Split-File.ps1 -inputFile "C:\path\to\your\input\file.ext" -outputDirectory "C:\BlueTeam" -chunkSizeInGB 2.7

PS> .\Split-File.ps1 (if params set before run)

.NOTES
Requires PowerShell v5+ and permissions to access the file to be split.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Split-File.ps1
#>

param(
    [string]$inputFile = "C:\path\to\your\input\file.ext", # Default input file to be split. It is recommended to first compress files before splitting for best results (i.e. - zip).
    [string]$outputDirectory = "C:\BlueTeam", # Default output directory
    [double]$chunkSizeInGB = 2.9 # Chunk size in GB
)

# Check if input file exists
if (-not (Test-Path -Path $inputFile)) {
    Write-Host "[!] Error: The specified input file does not exist: $inputFile" -ForegroundColor Red
    break
}

# Show progress for initializing
Write-Progress -Activity "Initializing" -Status "Checking file existence and permissions..." -PercentComplete 0

# Generate file hash for later comparison
Write-Progress -Activity "Calculating File Hash" -Status "Calculating hash for comparison..." -PercentComplete 10
$originalFileHash = (Get-FileHash -Path $inputFile).Hash
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "[*] Original File Hash: $originalFileHash" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Yellow

# Convert chunk size from GB to bytes
Write-Progress -Activity "Calculating Chunk Size" -Status "Converting chunk size to bytes..." -PercentComplete 20
[int64]$chunkSizeInBytes = [int64]($chunkSizeInGB * 1.073741824e9)

# Create output directory if it does not exist
Write-Progress -Activity "Creating Output Directory" -Status "Checking if output directory exists..." -PercentComplete 30
if (-not (Test-Path -Path $outputDirectory)) {
    Write-Progress -Activity "Creating Output Directory" -Status "Creating output directory..." -PercentComplete 40
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

# Retrieve file information
Write-Progress -Activity "Retrieving File Information" -Status "Fetching file information..." -PercentComplete 50
$fileInfo = Get-Item $inputFile
[int64]$fileSize = $fileInfo.Length
[int64]$currentPart = 1

# Open file stream for reading
Write-Progress -Activity "Opening File Stream" -Status "Opening file for reading..." -PercentComplete 60
$fileStream = [System.IO.File]::OpenRead($inputFile)
[int64]$bufferSize = 10MB
$buffer = New-Object Byte[] $bufferSize
[int64]$totalBytesRead = 0

# Split the file into chunks
while ($totalBytesRead -lt $fileSize) {
    $progressPercentage = [math]::Round(($totalBytesRead / $fileSize) * 100, 2)
    Write-Progress -Activity "Splitting File" -Status "Processing..." -PercentComplete $progressPercentage

    $outputFilePath = Join-Path $outputDirectory ("{0}_part{1:D4}.chunk" -f $fileInfo.BaseName, $currentPart)
    $chunkStream = [System.IO.File]::Create($outputFilePath)
    [int64]$bytesRemaining = $chunkSizeInBytes

    while ($bytesRemaining -gt 0) {
    
        # Read data in chunks
        [int64]$bytesToRead = [Math]::Min($bufferSize, $bytesRemaining)
        [int64]$actualRead = $fileStream.Read($buffer, 0, $bytesToRead)
        if ($actualRead -eq 0) { break }

        $chunkStream.Write($buffer, 0, $actualRead)
        $bytesRemaining -= $actualRead
        $totalBytesRead += $actualRead

        # Update progress within each chunk
        $progressPercentage = [math]::Round(($totalBytesRead / $fileSize) * 100, 2)
        Write-Progress -Activity "Splitting File" -Status "Processing chunk $currentPart..." -PercentComplete $progressPercentage
    }

    $chunkStream.Close()
    $currentPart++
}

$fileStream.Close()

# Indicate completion
Write-Progress -Activity "Splitting File" -Completed -Status "File split completed."
Write-Host "File split successfully into $($currentPart - 1) parts." -ForegroundColor Green
