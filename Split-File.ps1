<#
.SYNOPSIS
Splits a large file into smaller chunks to navigate EDR file size limitations during host quarantine. Compressing the file before splitting is strongly advised to minimize file size.

.DESCRIPTION
This PowerShell script addresses the challenge of extracting large files, such as memory dumps, from quarantined hosts constrained by EDR file size limits. It segments a large file into smaller, manageable chunks, each with a specified size in gigabytes. To optimize file size, compressing the original file prior to splitting is highly recommended.

The script generates files with a .chunk extension, the quantity of which depends on the original file size:
e.g., <file>_part0001.chunk, <file>_part0002.chunk, <file>_part0003.chunk, etc.

.PARAMETER inputFile
Specifies the path to the large file to be segmented.

.PARAMETER outputDirectory
Indicates the directory for storing the resulting chunk files.

.PARAMETER chunkSizeInGB
Determines the size of each individual file chunk in gigabytes.

.OUTPUTS
A series of chunk files in the designated output directory that are sequentially named to reflect their order and the base file name.

.EXAMPLE
PS> .\Split-File.ps1 -inputFile "C:\path\to\your\input\file.ext" -outputDirectory "C:\path\to\output\directory" -chunkSizeInGB 2.7

PS> .\Split-File.ps1 (Runs with pre-configured parameters hardcoded without command line inputs)

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Split-File.ps1

.NOTES
FileName: Split-File.ps1
Version: 1.0
Dependencies: PowerShell v5+

Use Merge-File.ps1 to reassemble the chunks and reverse the process of Split-File.ps1.
#>

param(
    [string]$inputFile = "C:\path\to\your\input\file.ext", # Replace with your default input file path
    [string]$outputDirectory = "C:\path\to\output\directory", # Replace with your default output directory
    [double]$chunkSizeInGB = 2.7 # Set the chunk size in GB
)

$originalHash = Get-FileHash -Path $inputFile
echo $originalHash

# Convert GB to bytes for chunk size
[int64]$chunkSize = [int64]($chunkSizeInGB * 1.073741824e9)

# Ensure output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory
}

# Get file info and calculate number of parts
$fileInfo = Get-Item $inputFile
[int64]$totalLength = $fileInfo.Length
[int64]$numParts = [Math]::Ceiling($totalLength / $chunkSize)
[int64]$currentPart = 1

# Prepare to read file
$fileStream = [System.IO.File]::OpenRead($inputFile)
[int64]$bufferSize = 10MB
$buffer = New-Object Byte[] $bufferSize
[int64]$bytesRead = 0

# Start splitting the file
while ($bytesRead -lt $totalLength) {
    # Adjusted file name format to exclude the date
    $outputFilePath = Join-Path $outputDirectory ("{0}_{1}_part{2:D4}.chunk" -f $fileInfo.BaseName, $fileInfo.Extension.TrimStart('.'), $currentPart)
    $filePartStream = [System.IO.File]::Create($outputFilePath)
    [int64]$bytesRemaining = $chunkSize

    while ($bytesRemaining -gt 0) {
        [int64]$bytesToRead = [Math]::Min($bufferSize, $bytesRemaining)
        [int64]$readLength = $fileStream.Read($buffer, 0, $bytesToRead)
        if ($readLength -eq 0) { break }

        $filePartStream.Write($buffer, 0, $readLength)
        $bytesRemaining -= $readLength
        $bytesRead += $readLength
    }

    $filePartStream.Close()
    $currentPart++
}

$fileStream.Close()
