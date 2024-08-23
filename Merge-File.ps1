<#
.SYNOPSIS
Reassembles chunked files back into their original large file format, reversing the process of the Split-File.ps1 script.

.DESCRIPTION
'Merge-File.ps1' is designed to recombine files that were previously split by 'Split-File.ps1', ideal for scenarios where large files need to be restored to their original state after being segmented to meet EDR file size limitations during host quarantine. The script merges the chunk files (.chunk) into the original file format.

CAUTION: The script will merge any file following the naming convention <file>_part0001.chunk, <file>_part0002.chunk, etc., located in the input directory. Ensure that only related chunk files are present in the directory, as the presence of unrelated files with a similar naming convention may interfere with the integrity of the reassembled file.

.PARAMETER inputDirectory
Specifies the directory containing the chunk files to be merged.

.PARAMETER outputFile
Designates the path and file name for storing the reassembled file.

.OUTPUTS
A single, reconstructed file at the specified output location, matching the hash of the original file.

.EXAMPLE
PS> .\Merge-File.ps1 -inputDirectory "C:\path\to\input\directory" -outputFile "C:\path\to\output\file.ext"
PS> .\Merge-File.ps1 (Runs with pre-configured parameters hardcoded without command line inputs)

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Split-File.ps1

.NOTES
FileName: Merge-File.ps1
Version: 1.0
Dependencies: PowerShell v5+

Intended for use with Split-File.ps1 to reverse the file splitting process. Carefully manage the input directory to avoid unintended file merges.
#>

param(
    [string]$inputDirectory = "C:\path\to\input\directory", # Replace with your default input directory
    [string]$outputFile = "C:\path\to\output\file.ext" # Replace with your default output file path
)

# Get all chunk files in the specified directory and sort them by name
$chunkFiles = Get-ChildItem -Path $inputDirectory -Filter "*_part*.chunk" | Sort-Object Name

# Ensure output directory exists
$outputDir = Split-Path $outputFile
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir
}

# Create output file stream
$outputFileStream = [System.IO.File]::Create($outputFile)
[int64]$bufferSize = 10MB
$buffer = New-Object Byte[] $bufferSize

# Loop through each chunk file and write its contents to the output file
foreach ($chunkFile in $chunkFiles) {
    $inputFileStream = [System.IO.File]::OpenRead($chunkFile.FullName)

    while (($readLength = $inputFileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $outputFileStream.Write($buffer, 0, $readLength)
    }

    $inputFileStream.Close()
}

$outputFileStream.Close()
Get-FileHash -Path $outputFile
