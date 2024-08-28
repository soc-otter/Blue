<#
.SYNOPSIS
Extracts the complete DNS client cache and exports it to a CSV file.

.DESCRIPTION
This script retrieves DNS client cache entries. It organizes the extracted data and saves it to a CSV file.

.EXAMPLE
PS> .\DNS_Client_Cache.ps1

.NOTES
Requires PowerShell v5+.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/DNS_Client_Cache.ps1
#>

# Define the output directory and file name
$exportDirectory = 'C:\BlueTeam'
$exportFileName = 'DNS_Client_Cache.csv'
$exportFilePath = Join-Path -Path $exportDirectory -ChildPath $exportFileName

# Create the output directory if it doesn't exist
if (-not (Test-Path -Path $exportDirectory)) {
    New-Item -ItemType Directory -Path $exportDirectory -Force | Out-Null
}

# Fetch the DNS client cache in list form to avoid truncation
$dnsCacheData = Get-DnsClientCache | Format-List | Out-String

# Delimit the cache data to process each entry individually
$entrySeparator = 'Entry      :'
$entryDataBlocks = ($dnsCacheData -split $entrySeparator) | Where-Object { $_.Trim() -ne '' }

# Function to parse text into a hashtable format
function Parse-DnsEntry($entryText) {
    $entryHash = @{}
    $entryText.Split("`n") | ForEach-Object {
        $trimmedLine = $_.Trim()
        if ($trimmedLine -ne '') {
            $lineParts = $trimmedLine -split ':', 2
            $entryHash[$lineParts[0].Trim()] = $lineParts[1].Trim()
        }
    }
    return $entryHash
}

# Process each entry block and build a collection of custom objects
$dnsEntryObjects = foreach ($entryBlock in $entryDataBlocks) {
    $parsedEntry = Parse-DnsEntry -entryText ($entrySeparator + $entryBlock)
    [PSCustomObject]@{
        EntryID    = $parsedEntry["Entry"]
        HostName   = $parsedEntry["RecordName"]
        Type       = $parsedEntry["RecordType"]
        Status     = $parsedEntry["Status"]
        Section    = $parsedEntry["Section"]
        TTL        = $parsedEntry["TimeToLive"]
        DataSize   = $parsedEntry["DataLength"]
        IPAddress  = $parsedEntry["Data"]
    }
}

# Export the DNS entry objects to a CSV file
$dnsEntryObjects | Export-Csv -Path $exportFilePath -NoTypeInformation
