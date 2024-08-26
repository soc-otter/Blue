<#
.SYNOPSIS
Scans for potentially masquerading executables and collects detailed information about them.

.DESCRIPTION
This script scans the system drive (or an optionally specified path) for files with 'MZ' headers that do not have typical executable extensions. It gathers information about each file, including size, owner, digital signature status, hash values, and Zone Identifier details (if present). The results are sorted by creation time with the most recent files appearing at the top of the CSV.

The MZ header is like a telltale sign that helps uncover a file's true identity. Even if a file is named "legit.png" to appear like a harmless image, the presence of the MZ header at the beginning of the file reveals that it's actually an executable likely disguised with a misleading extension. This header, marked by the characters "MZ", is an indicator that the file contains executable code and not just image data.

.NOTES
Requires PowerShell v5+ and admin privileges.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Masquerading_Executables.ps1

.EXAMPLE
PS> .\Masquerading_Executables.ps1
#>

# Output directory for CSV files
$outputDirectory = 'C:\BlueTeam'
$outputCsvFile = Join-Path $outputDirectory "Masquerading_Executables.csv"
$tempCsvFile = Join-Path $outputDirectory "Temp_Masquerading_Executables.csv"

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Optionally specify a different root path to scan
$rootPath = $env:SystemDrive + "\"
#$rootPath = "C:\Users"  # Uncomment to scan a different path instead of the entire system drive

# Define exclusions
$excludeFolders = @(
    #"C:\specific\folder\to\exclude\1",
    "C:\Windows\SoftwareDistribution\Download"
)

$excludeExactPaths = @(
    #"C:\specific\file\to\exclude\1.txt",
    "C:\specific\file\to\exclude\2.txt"
)

# Ignored file extensions (as a hashtable for faster lookup)
$ignoreExtensions = @{
    '.exe'=1; '.dll'=1; '.sys'=1; '.scr'=1; '.drv'=1; '.ocx'=1; '.cpl'=1; '.efi'=1; '.bin'=1; '.sfx'=1; '.mui'=1;
    '.tlb'=1; '.rll'=1; '.pyd'=1; '.olb'=1; '.dub'=1; '.fae'=1; '.sam'=1; '.lex'=1; '.flt'=1; '.odf'=1; '.com'=1;
    '.winmd'=1; '.dll_ko'=1; '.iltoc'=1; '.ildll'=1; '.toc'=1; '.dic'=1; '.xll'=1; '.cnv'=1; '.dat'=1; '.node'=1;
    '.bak'=1; '.old'=1; '.asi'=1; '.tsp'=1; '.temp'=1; '.uni'=1; '.fil'=1; '.msstyles'=1; '.rs'=1; '.ax'=1; '.0'=1;
    '.acm'=1; '.ime'=1; '.tmp'=1
}

# Function to check if a path should be excluded
function Test-ShouldExclude {
    param (
        [string]$path
    )
    
    # Check for exact path exclusions
    if ($excludeExactPaths -contains $path) {
        return $true
    }
    
    # Check for folder exclusions
    foreach ($folder in $excludeFolders) {
        if ($path.StartsWith($folder, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    
    return $false
}

# Function to format byte size
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB) {
        $Size /= 1KB
        $UnitIndex++
    }
    "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
}

# Function to retrieve file owner
function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath).Owner
    } catch {
        "-"
    }
}

# Function to retrieve Zone.Identifier ADS information
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
                '^HostUrl=(.+)' { $hostUrl = $matches[1] }
            }
        }
    } catch {}

    [PSCustomObject]@{
        ZoneId = $zoneId
        ReferrerUrl = $referrerUrl
        HostUrl = $hostUrl
    }
}

# Function to add a hyphen for null or empty values
function Add-Hyphen {
    param ($value)
    if ($null -eq $value -or [string]::IsNullOrEmpty($value)) { "-" } else { $value }
}

# Initialize temporary CSV file with headers
$csvHeaders = "CreationTime,Full Path,File Size,File Owner,Status,IsOSBinary,StatusMessage,LastWriteTime,LastAccessTime,SignerCertificate,TimeStamperCertificate,SHA256,ZoneId,ReferrerUrl,HostUrl"
Set-Content -Path $tempCsvFile -Value $csvHeaders

# Cache for file owners to reduce repetitive ACL lookups
$cachedOwners = @{}

# Scan and process files
$itemsProcessed = 0

Get-ChildItem -Path $rootPath -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object { 
        $_.Length -ge 512 -and 
        -not $ignoreExtensions.ContainsKey($_.Extension) -and
        -not (Test-ShouldExclude $_.FullName)
    } | 
    ForEach-Object {
    $item = $_
    $itemsProcessed++
    if ($itemsProcessed % 100 -eq 0) {
        Write-Progress -Activity "Scanning for Masquerading Executables" -Status "Processed $itemsProcessed files. Looking for more.."  -PercentComplete 0
    }

    try {
        # Read the first 2 bytes to check for MZ header
        $byteArray = New-Object byte[] 2
        try {
            $stream = [System.IO.File]::OpenRead($item.FullName)
            $stream.Read($byteArray, 0, 2) | Out-Null
            $stream.Close()
        }
        catch [System.IO.IOException] {
            Write-Warning "Unable to access file $($item.FullName): File is in use by another process."
            return
        }
        catch {
            Write-Warning "Error accessing file $($item.FullName): $($_.Exception.Message)"
            return
        }

        if ($byteArray[0] -eq 0x4D -and $byteArray[1] -eq 0x5A) {
            $signature = Get-AuthenticodeSignature -FilePath $item.FullName

            # Skip known OS binaries
            if ($signature.IsOSBinary -eq $true) { return }

            # Get file owner (use cached value if available)
            if (-not $cachedOwners.ContainsKey($item.FullName)) {
                $cachedOwners[$item.FullName] = Get-FileOwner -FilePath $item.FullName
            }
            $fileOwner = $cachedOwners[$item.FullName]

            $zoneInfo = Get-ZoneIdentifierInfo -filePath $item.FullName
            $sha256 = (Get-FileHash -Path $item.FullName -Algorithm SHA256).Hash

            $fileDetails = [PSCustomObject]@{
                "CreationTime" = $item.CreationTime
                "Full Path" = Add-Hyphen $item.FullName
                "File Size" = Add-Hyphen (Get-FormattedByteSize -ByteSize $item.Length)
                "File Owner" = Add-Hyphen $fileOwner
                "Status" = Add-Hyphen $signature.Status
                "IsOSBinary" = Add-Hyphen $signature.IsOSBinary
                "StatusMessage" = Add-Hyphen $signature.StatusMessage
                "LastWriteTime" = Add-Hyphen $item.LastWriteTime
                "LastAccessTime" = Add-Hyphen $item.LastAccessTime
                "SignerCertificate" = Add-Hyphen ($signature.SignerCertificate | Select-Object -ExpandProperty Subject -ErrorAction SilentlyContinue)
                "TimeStamperCertificate" = Add-Hyphen ($signature.TimeStamperCertificate | Select-Object -ExpandProperty Subject -ErrorAction SilentlyContinue)
                "SHA256" = Add-Hyphen $sha256
                "ZoneId" = Add-Hyphen $zoneInfo.ZoneId
                "ReferrerUrl" = Add-Hyphen $zoneInfo.ReferrerUrl
                "HostUrl" = Add-Hyphen $zoneInfo.HostUrl
            }

            # Append the result to the temporary CSV file immediately
            $fileDetails | Export-Csv -Path $tempCsvFile -Append -NoTypeInformation
        }
    } catch {
        Write-Warning "Error processing file $($item.FullName): $($_.Exception.Message)"
    }
}

Write-Progress -Activity "Scanning for Masquerading Executables" -Status "Sorting results..." -PercentComplete 90

# Sort the temporary CSV file by CreationTime and write to the final CSV file
Import-Csv $tempCsvFile | Sort-Object { [DateTime]::Parse($_.CreationTime) } -Descending | 
    Export-Csv -Path $outputCsvFile -NoTypeInformation

# Remove the temporary file
Remove-Item $tempCsvFile

Write-Progress -Activity "Scanning for Masquerading Executables" -Status "Completed" -PercentComplete 100
