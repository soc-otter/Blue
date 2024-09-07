<#

.SYNOPSIS
Retrieves details of installed applications.

.DESCRIPTION
This script retrieves information about installed applications and writes results to a CSV.

.NOTES
- Requires PowerShell v5 and admin rights.
- May not capture all software installed through non-standard methods (i.e. - portable applications, software installed via custom scripts, or applications installed in user directories without modifying the registry).

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Installed_Applications.ps1

.EXAMPLE
PS> .\Installed_Applications.ps1

#>

$outputDirectory = 'C:\BlueTeam'
$csvFileName = Join-Path $outputDirectory "Installed_Applications.csv"

if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$sizeUnits = @("B", "KB", "MB", "GB", "TB", "PB")

function Get-AppInfo {
    param ($app, $keyPath)
    
    $size = if ($app.EstimatedSize -and [int]$app.EstimatedSize -ne 0) {
        $s = $app.EstimatedSize
        $i = 0
        while ($s -ge 1KB -and $i -lt 5) { $s /= 1KB; $i++ }
        "{0:N2} {1}" -f $s, $sizeUnits[$i]
    } else { '-' }

    [PSCustomObject]@{
        DisplayName           = if ($app.DisplayName)          { $app.DisplayName }          else { '-' }
        InstallDate           = if ($app.InstallDate)          { $app.InstallDate }          else { '-' }
        Publisher             = if ($app.Publisher)            { $app.Publisher }            else { '-' }
        DisplayVersion        = if ($app.DisplayVersion)       { $app.DisplayVersion }       else { '-' }
        InstallLocation       = if ($app.InstallLocation)      { $app.InstallLocation }      else { '-' }
        URLInfoAbout          = if ($app.URLInfoAbout)         { $app.URLInfoAbout }         else { '-' }
        URLUpdateInfo         = if ($app.URLUpdateInfo)        { $app.URLUpdateInfo }        else { '-' }
        EstimatedSize         = if ($app.EstimatedSize)        { $app.EstimatedSize }        else { '-' }
        Size                  = $size
        Comments              = if ($app.Comments)             { $app.Comments }             else { '-' }
        Contact               = if ($app.Contact)              { $app.Contact }              else { '-' }
        DisplayIcon           = if ($app.DisplayIcon)          { $app.DisplayIcon }          else { '-' }
        UninstallString       = if ($app.UninstallString)      { $app.UninstallString }      else { '-' }
        QuietUninstallString  = if ($app.QuietUninstallString) { $app.QuietUninstallString } else { '-' }
        RegistryHive          = $keyPath
        Hostname              = $env:COMPUTERNAME
    }
}

Write-Progress -Activity "Collecting Application Data" -Status "Initializing" -PercentComplete 10

$installedApps = @()
$totalPaths = $registryPaths.Count
$pathCounter = 0

foreach ($path in $registryPaths) {
    $pathCounter++
    $pathProgress = ($pathCounter / $totalPaths) * 80  # 80% of progress bar dedicated to data collection

    Write-Progress -Activity "Collecting Application Data" -Status "Processing registry path $pathCounter of $totalPaths" -PercentComplete (10 + $pathProgress)

    $apps = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
        $app = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        if ($app.DisplayName) { Get-AppInfo $app $_.PSPath }
    }
    $installedApps += $apps
}

Write-Progress -Activity "Processing Data" -Status "Sorting applications" -PercentComplete 90
$sortedApps = $installedApps | Sort-Object InstallDate -Descending

Write-Progress -Activity "Exporting Data" -Status "Saving to CSV" -PercentComplete 95
$sortedApps | Export-Csv -Path $csvFileName -NoTypeInformation

Write-Progress -Activity "Completing Process" -Status "Results saved to $csvFileName" -PercentComplete 100
Write-Progress -Activity "Completing Process" -Completed
