<#
.SYNOPSIS
Reassembles split files back into their original format.

.DESCRIPTION
'Merge-File.ps1' is designed to help put back together files that were previously split using 'Split-File.ps1'. It takes all the chunk files (.chunk) from a specified directory and merges them into a single, complete file.

CAUTION: Make sure only the chunk files that follow the naming pattern (like <file>_part0001.chunk, <file>_part0002.chunk, etc.) are in the input directory to avoid merging errors.

.EXAMPLE
PS> .\Merge-File.ps1 -inputDirectory "C:\path\to\input\directory" -outputFile "C:\path\to\output\file.ext"

PS> .\Merge-File.ps1 (if params set before run)

.NOTES
Requires PowerShell v5+.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Merge-File.ps1
#>


param(
    [string]$inputDirectory = "C:\BlueTeam", # Default input directory containing chunk files
    [string]$outputFile = "C:\path\to\output\file.ext" # Default output file path
)

# Check if input directory exists
if (-not (Test-Path -Path $inputDirectory)) {
    Write-Host "[!] Error: The specified input directory does not exist: $inputDirectory" -ForegroundColor Red
    exit 1
}

# Show progress for initializing
Write-Progress -Activity "Initializing" -Status "Fetching chunk files..." -PercentComplete 0

# Get all chunk files in the specified directory and sort them by name
$chunkFiles = Get-ChildItem -Path $inputDirectory -Filter "*_part*.chunk" | Sort-Object Name

if ($chunkFiles.Count -eq 0) {
    Write-Host "[!] Error: No chunk files found in the specified directory." -ForegroundColor Red
    exit 1
}

# Calculate the total size of all chunk files
$totalSize = ($chunkFiles | Measure-Object Length -Sum).Sum

# Ensure output directory exists
$outputDir = Split-Path $outputFile
if (-not (Test-Path -Path $outputDir)) {
    Write-Progress -Activity "Creating Output Directory" -Status "Creating directory..." -PercentComplete 10
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# Create output file stream
Write-Progress -Activity "Merging Files" -Status "Creating output file stream..." -PercentComplete 20
$outputFileStream = [System.IO.File]::Create($outputFile)
[int64]$bufferSize = 10MB
$buffer = New-Object Byte[] $bufferSize
[int64]$totalBytesWritten = 0

# Loop through each chunk file and write its contents to the output file
foreach ($chunkFile in $chunkFiles) {
    $inputFileStream = [System.IO.File]::OpenRead($chunkFile.FullName)

    while (($readLength = $inputFileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        try {
            $outputFileStream.Write($buffer, 0, $readLength)
            $totalBytesWritten += $readLength
        } catch {
            Write-Host "[!] Error: Could not write to the output file. Check disk space or permissions." -ForegroundColor Red
            $inputFileStream.Close()
            $outputFileStream.Close()
            exit 1
        }

        # Correct PercentComplete calculation
        $progressPercentage = [math]::Round(($totalBytesWritten / $totalSize) * 100, 2)
        if ($progressPercentage -gt 100) { $progressPercentage = 100 }
        
        # Update progress
        Write-Progress -Activity "Merging Files" -Status "Processing $($chunkFile.Name)..." -PercentComplete $progressPercentage
    }

    $inputFileStream.Close()
}

$outputFileStream.Close()

# Show progress for hash calculation
Write-Progress -Activity "Calculating Hash" -Status "Calculating hash of the reassembled file..." -PercentComplete 100

# Calculate and display the hash and file path for verification
$hashResult = Get-FileHash -Path $outputFile
Write-Progress -Activity "Calculating Hash" -Completed -Status "Hash calculation completed."

# Display the hash and output path
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "[*] Reassembled File Hash: $($hashResult.Hash)" -ForegroundColor Cyan
Write-Host "[*] File Written to      : $($hashResult.Path)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Yellow
