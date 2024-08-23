<#
.SYNOPSIS
Identifies services with unquoted paths containing spaces.

.DESCRIPTION
This script scans all services on a Windows system to identify those with unquoted executable paths that contain spaces. Such paths can be exploited by attackers who may place malicious executables in specific locations on the filesystem. If the service is executed, Windows might run the malicious executable instead to gain privilege escalation. The script exports the identified services and associated risks to a CSV for further analysis.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Vulnerable_Unquoted_Service_Paths.ps1

.EXAMPLE
PS> .\Vulnerable_Unquoted_Service_Paths.ps1
#>

function Get-UniqueParentDirectories {
    param (
        [string[]]$paths
    )
    $uniqueParents = @{}
    foreach ($path in $paths) {
        $parent = Split-Path $path -Parent
        while ($parent -and !(Test-Path $parent)) {
            $parent = Split-Path $parent -Parent
        }
        if ($parent -and -not $uniqueParents.ContainsKey($parent)) {
            $uniqueParents[$parent] = $true
        }
    }
    return $uniqueParents.Keys
}

function Get-PotentiallyVulnerablePaths {
    param (
        [string]$filePath
    )
    $pathWithoutExe = $filePath -replace "\.exe$", ""
    $pathSegments = $pathWithoutExe -split '\\'
    $vulnerablePaths = @()
    $accumulatedPath = ""

    foreach ($segment in $pathSegments) {
        if ($accumulatedPath -ne "") {
            $accumulatedPath += "\"
        }
        $accumulatedPath += $segment

        $subSegments = $accumulatedPath -split ' '
        for ($i = 0; $i -lt $subSegments.Length - 1; $i++) {
            $potentialVulnerablePath = ($subSegments[0..$i] -join ' ') + ".exe"
            $vulnerablePaths += $potentialVulnerablePath
        }
    }

    return $vulnerablePaths | Select-Object -Unique
}

# Set the output directory
$outputDirectory = 'C:\BlueTeam'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Retrieve services with potentially vulnerable unquoted paths
$services = Get-CimInstance -ClassName win32_service | 
            Select-Object ProcessId, Name, State, StartName, @{Name="FilePath"; Expression={if ($_.PathName -notmatch '^".*"$' -and $_.PathName -like '* *.exe') { $_.PathName -replace '.*?([^"]+\.exe).*', '$1' }}} | 
            Where-Object FilePath

$serviceData = @()

foreach ($service in $services) {
    $vulnerablePaths = Get-PotentiallyVulnerablePaths -filePath $service.FilePath
    $uniqueParentDirectories = Get-UniqueParentDirectories -paths $vulnerablePaths

    $formattedIcaclsOutput = @()
    foreach ($parent in $uniqueParentDirectories) {
        $icaclsOutput = icacls $parent 2>&1 | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }  # Trim and remove empty lines
        $formattedIcaclsOutput += "icacls `"$parent`":`n" + ($icaclsOutput -join "`n")  # No leading newline
    }

    $obj = New-Object PSObject -Property @{
        ProcessId = $service.ProcessId
        Name = $service.Name
        State = $service.State
        StartName = $service.StartName
        FilePath = $service.FilePath
        PotentiallyVulnerableAt = ($vulnerablePaths -join ', ')
        FormattedIcaclsOutput = $formattedIcaclsOutput -join "`n"
    }

    $serviceData += $obj
}

# Export to CSV only if data exists
if ($serviceData.Count -gt 0) {
    $csvPath = Join-Path $outputDirectory "Vulnerable_Unquoted_Service_Paths.csv"
    $serviceData | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Progress -Activity "Service Path Analysis" -Status "Exported results to $csvPath" -PercentComplete 100 -Completed
} else {
    Write-Progress -Activity "Service Path Analysis" -Status "No vulnerable service paths found." -PercentComplete 100 -Completed
}
