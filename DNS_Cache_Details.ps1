<#
.SYNOPSIS
Captures the DNS client cache and exports it to a CSV.

.DESCRIPTION
This script is useful for identifying adversarial behavior by capturing and analyzing the DNS client cache, which logs domain name resolutions on the system. DNS queries are often used by malicious actors for command and control (C2) communication, data exfiltration, or redirecting users to malicious sites. By exporting the complete DNS client cache to a CSV, security analysts can scrutinize domain requests, identify suspicious or unusual domain names, and correlate these with known malicious indicators. This helps in detecting, investigating, and mitigating potential cyber threats on the system.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/DNS_Cache_Details.ps1

.EXAMPLE
PS> .\DNS_Cache_Details.ps1
#>


# Set the output directory and file name
$outputDirectory = 'C:\BlueTeam'
$outputFileName = 'DNS_Cache_Information.csv'
$outputFilePath = Join-Path -Path $outputDirectory -ChildPath $outputFileName

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Convert a block of text into a hashtable
function ConvertTo-HashTable {
    param ($textBlock)
    $hashTable = @{}
    $textBlock.Split("`n") | ForEach-Object {
        $line = $_.Trim()
        if ($line) {
            $parts = $line -split ':', 2
            $hashTable[$parts[0].Trim()] = $parts[1].Trim()
        }
    }
    return $hashTable
}

# Get DNS client cache and process it
$dnsCacheEntries = Get-DnsClientCache | Format-List | Out-String
$delimiter = 'Entry      :'
$entryBlocks = ($dnsCacheEntries -split $delimiter) | Where-Object { $_.Trim() }

# Create objects from each record
$dnsObjects = foreach ($block in $entryBlocks) {
    $hashTable = ConvertTo-HashTable -textBlock ($delimiter + $block)
    [PSCustomObject]@{
        Entry      = $hashTable["Entry"]
        RecordName = $hashTable["RecordName"]
        RecordType = $hashTable["RecordType"]
        Status     = $hashTable["Status"]
        Section    = $hashTable["Section"]
        TimeToLive = $hashTable["TimeToLive"]
        DataLength = $hashTable["DataLength"]
        Data       = $hashTable["Data"]
    }
}

# Export the DNS objects to CSV
$dnsObjects | Export-Csv -Path $outputFilePath -NoTypeInformation
