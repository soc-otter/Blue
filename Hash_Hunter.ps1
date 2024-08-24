<#
.SYNOPSIS
Identifies files matching provided hash values, without needing to know the alorithm they were generated with, extracting detailed file information.

.DESCRIPTION
This PowerShell script recursively scans directories for files that match any provided hash value. It supports multiple algorithms and doesn't require prior knowledge of which algorithm was used to generate the hashes. If matches are found, it records details such as matched algorithm, file size, location, owner, and timestamps.

.PARAMETER Paths
An array of directory paths to recursively search for matching file hashes.

.PARAMETER Algorithms
A list of cryptographic hash algorithms to apply when computing file hashes.

.PARAMETER Hashes
A collection of hash values to check against. Can be a string, file, or CSV input. At least one method to feed script hashes must be chosen by uncommenting a '$Hashes' variable of your choosing. 

.OUTPUTS
A CSV file at the specified path with detailed information on each file that matches the provided hashes.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Basic_System_Prefetch_Details.ps1

.EXAMPLE
PS> .\Hash_Hunter.ps1

.NOTES
FileName: Hash_Hunter.ps1
Version: 1.0
Dependencies: PowerShell v5+
#>

# User-defined variables
$Paths = @("C:\path\to\search\1", "C:\path\to\search\2") # Recursive
$outputDirectory = 'C:\BlueTeam'
$outputFileName = "Files_Matching_Hashes_Found.csv"

# If you know the algorithms of your hashes, specify them here for speed. If not, leave as is and the script will attempt to find it.
$Algorithms = @("MD5", "SHA1", "SHA256", "SHA384", "SHA512")

# Method to feed in hashes (must pick one by uncommenting a $Hashes variable)
#$Hashes = "hash1 hash2 hash3 hash4" -split " "
#$Hashes = Get-Content -Path "C:\path\to\hashes.txt"
#$Hashes = Import-Csv -Path "C:\path\to\hashes.csv" | Select-Object -ExpandProperty Hashes # Assumes column name is 'Hashes'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}
$outputFilePath = Join-Path -Path $outputDirectory -ChildPath $outputFileName

# Convert the hash list to a hashtable for faster lookup
$HashLookupTable = @{}
foreach ($Hash in $Hashes) {
    $HashLookupTable[$Hash] = $true
}

# Function to convert file size into a human-readable format
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $ByteSize | ForEach-Object {
        $UnitIndex = 0
        $Size = [math]::Round($_, 2)
        while ($Size -ge 1KB) {
            $Size = $Size / 1KB
            $UnitIndex++
        }
        "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
    }
}

function Get-FileOwner {
    param ([string]$FilePath)
    try {
        $acl = Get-Acl $FilePath
        return $acl.Owner
    } catch {
        return $null
    }
}

# Function to process files and check hashes
function Process-File {
    param($File, $Algorithms, $HashLookupTable, $OutputFilePath)
    foreach ($Algorithm in $Algorithms) {
        try {
            $FileHash = Get-FileHash -Path $File.FullName -Algorithm $Algorithm -ErrorAction Stop
            if ($HashLookupTable.ContainsKey($FileHash.Hash)) {
                $fileSizeFormatted = Get-FormattedByteSize -ByteSize $File.Length
                $fileOwner = Get-FileOwner -FilePath $File.FullName

                $result = [PSCustomObject]@{
                    MatchedAlgorithm = $Algorithm
                    Hash = $FileHash.Hash
                    Path = $File.FullName
                    FileSize = $fileSizeFormatted
                    Owner = $fileOwner
                    Extension = $File.Extension
                    CreationTime = $File.CreationTime.ToString('o')
                    LastWriteTime = $File.LastWriteTime.ToString('o')
                    LastAccessTime = $File.LastAccessTime.ToString('o')
                }
                $result | Export-Csv -Path $OutputFilePath -NoTypeInformation -Append
            }
        }
        catch {
            #
        }
    }
}

# Main loop
foreach ($Path in $Paths) {
    $Files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue
    foreach ($File in $Files) {
        Process-File -File $File -Algorithms $Algorithms -HashLookupTable $HashLookupTable -OutputFilePath $outputFilePath
    }
}
