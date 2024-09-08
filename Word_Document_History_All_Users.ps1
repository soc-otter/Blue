<#

.SYNOPSIS
Grabs the history of documents opened in Microsoft Word for each user.

.DESCRIPTION
The script checks the HKU registry hive for Word document reading locations and compiles a list of recently opened documents. Output is written to a CSV.

.EXAMPLE
PS> .\Word_Document_History_All_Users.ps1

.NOTES
This script may require administrative privileges to access registry keys and file paths.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Word_Document_History_All_Users.ps1

.EXAMPLE
PS> .\Word_Document_History_All_Users.ps1

#>

# Define the output directory and file
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory "Word_Document_History_All_Users.csv"

# Create the output directory if it doesn't exist
New-Item -ItemType Directory -Path $outputDirectory -Force -ErrorAction SilentlyContinue | Out-Null

# Function to resolve SID to Username
function Get-UsernameFromSID($SID) {
    try {
        return ([System.Security.Principal.SecurityIdentifier]$SID).Translate([System.Security.Principal.NTAccount]).Value.Trim()
    } catch {
        return $SID.Trim()
    }
}

# Function to get Zone Identifier data
function Get-ZoneIdentifier($filePath) {
    try {
        $content = Get-Content -Path $filePath -Stream Zone.Identifier -ErrorAction Stop
        return @{
            ZoneId = (($content | Where-Object { $_ -match 'ZoneId=' }) -replace 'ZoneId=','' -replace '\s+', '').Trim()
            ReferrerUrl = (($content | Where-Object { $_ -match 'ReferrerUrl=' }) -replace 'ReferrerUrl=','').Trim()
            HostUrl = (($content | Where-Object { $_ -match 'HostUrl=' }) -replace 'HostUrl=','').Trim()
        }
    } catch {
        return @{ZoneId = "-"; ReferrerUrl = "-"; HostUrl = "-"}
    }
}

# Start
$registryEntries = Get-ChildItem 'Registry::HKU\*\Software\Microsoft\Office\*\Word\Reading Locations\*' -ErrorAction SilentlyContinue
$totalEntries = $registryEntries.Count
$currentEntry = 0

$results = $registryEntries | ForEach-Object {
    $currentEntry++
    Write-Progress -Activity "Processing Word document history" -Status "Entry $currentEntry of $totalEntries" -PercentComplete (($currentEntry / $totalEntries) * 100)

    $sid = $_.PsPath.Split('\')[2]
    $properties = $_ | Get-ItemProperty

    if ($properties.'File Path') {
        $filePath = $properties.'File Path'.Trim()
        $fileInfo = Get-Item -Path $filePath -ErrorAction SilentlyContinue
        $zoneInfo = Get-ZoneIdentifier -filePath $filePath

        $lastOpenedDateTime = if ($properties.'Datetime' -is [string]) {
            [DateTime]::ParseExact($properties.'Datetime'.Trim(), 'yyyy-MM-ddTHH:mm', $null)
        } else {
            [DateTime]::FromFileTime([BitConverter]::ToInt64($properties.'Datetime', 0))
        }

        [PSCustomObject]@{
            Username = Get-UsernameFromSID -SID $sid
            SID = $sid.Trim()
            DocumentPath = $filePath
            SHA256Hash = if ($fileInfo) { (Get-FileHash -Path $filePath -Algorithm SHA256).Hash } else { "File not found" }
            LastOpenedUTC = $lastOpenedDateTime.ToUniversalTime()
            LastOpenedLocalTime = $lastOpenedDateTime
            Size = if ($fileInfo) { "{0:N2} KB" -f ($fileInfo.Length / 1KB) } else { "-" }
            Owner = if ($fileInfo) { (Get-Acl $filePath).Owner.Trim() } else { "-" }
            ZoneId = $zoneInfo.ZoneId
            ReferrerUrl = $zoneInfo.ReferrerUrl
            HostUrl = $zoneInfo.HostUrl
            Position = $properties.'Position'.ToString().Trim()
            RegistryPath = $properties.PSPath.Trim()
        }
    }
}

Write-Progress -Activity "Processing Word document history" -Completed

# Sort results and export to CSV
$results | Sort-Object LastOpenedUTC -Descending | Export-Csv -Path $outputFile -NoTypeInformation

Write-Progress -Activity "Exporting results" -Status "Complete" -Completed
