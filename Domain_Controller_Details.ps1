<#

.SYNOPSIS
Retrieves information about all domain controllers in the current Active Directory domain.

.DESCRIPTION
This script gathers information about domain controllers in the Active Directory domain of the host machine and writes results to a CSV. It identifies the primary domain controller and collects data about each DC.

.NOTES
Requires PowerShell v5+ and administrative privileges. Ensure that this script is run in an environment where the Active Directory domain is accessible.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Domain_Controller_Details.ps1

.EXAMPLE
PS> .\Domain_Controller_Details.ps1

#>

# Function to replace empty or null values with a hyphen, preserving TRUE/FALSE
function Replace-EmptyValue {
    param([object]$Value)
    if ($null -eq $Value -or ($Value -eq '' -and $Value -isnot [bool])) {
        return '-'
    }
    return $Value
}

# Check and import Active Directory module
if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory
    } else {
        Write-Progress -Activity "Checking Prerequisites" -Status "Active Directory module not available" -PercentComplete 100
        Write-Error "Active Directory module is not available. Please install RSAT tools."
        exit
    }
}

Write-Progress -Activity "Retrieving Domain Information" -Status "Getting current domain..." -PercentComplete 10
$currentDomain = Get-ADDomain

Write-Progress -Activity "Retrieving Domain Controller Information" -Status "Getting list of domain controllers..." -PercentComplete 20
$domainControllers = Get-ADDomainController -Filter *

Write-Progress -Activity "Retrieving Domain Controller Information" -Status "Identifying Primary Domain Controller..." -PercentComplete 30
$primaryDomainController = $currentDomain.PDCEmulator

# Initialize an array to store domain controller info
$domainControllerInfo = @()

# Process domain controller information
$totalDCs = $domainControllers.Count
for ($i = 0; $i -lt $totalDCs; $i++) {
    $dc = $domainControllers[$i]
    $percentComplete = 30 + (($i + 1) / $totalDCs * 60)
    Write-Progress -Activity "Retrieving Domain Controller Information" -Status "Processing $($dc.HostName) ($($i+1) of $totalDCs)" -PercentComplete $percentComplete
    
    $dcComputer = Get-ADComputer $dc.Name -Properties *
    $domainControllerInfo += [PSCustomObject]@{
        Name                    = Replace-EmptyValue $dc.HostName
        IPV4Address             = Replace-EmptyValue $dc.IPv4Address
        IPV6Address             = Replace-EmptyValue $dcComputer.IPv6Address
        Site                    = Replace-EmptyValue $dc.Site
        Forest                  = Replace-EmptyValue $dc.Forest
        Domain                  = Replace-EmptyValue $dc.Domain
        IsPrimaryDC             = $dc.HostName -eq $primaryDomainController
        OperatingSystem         = Replace-EmptyValue $dcComputer.OperatingSystem
        OperatingSystemVersion  = Replace-EmptyValue $dcComputer.OperatingSystemVersion
        IsGlobalCatalog         = $dc.IsGlobalCatalog
        IsReadOnly              = $dc.IsReadOnly
        Enabled                 = $dcComputer.Enabled
        Created                 = Replace-EmptyValue $dcComputer.Created
        Modified                = Replace-EmptyValue $dcComputer.Modified
        LastLogonDate           = Replace-EmptyValue $dcComputer.LastLogonDate
        LogonCount              = Replace-EmptyValue $dcComputer.LogonCount
        DistinguishedName       = Replace-EmptyValue $dc.DistinguishedName
        DNSHostName             = Replace-EmptyValue $dc.DNSHostName
        ServicePrincipalNames   = Replace-EmptyValue ($dcComputer.ServicePrincipalNames -join '; ')
        FSMORoles               = Replace-EmptyValue ($dc.OperationMasterRoles -join '; ')
    }
}

Write-Progress -Activity "Retrieving Domain Controller Information" -Status "Processing complete" -PercentComplete 90

# Check if we have any results
if ($domainControllerInfo.Count -gt 0) {

    # Prepare output path
    $outputPath = "C:\BlueTeam\Domain_Controller_Details.csv"
    $outputDirectory = Split-Path -Path $outputPath -Parent

    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }

    Write-Progress -Activity "Exporting Domain Controller Information" -Status "Saving to CSV..." -PercentComplete 95

    # Export to CSV
    $domainControllerInfo | Export-Csv -Path $outputPath -NoTypeInformation

    Write-Progress -Activity "Exporting Domain Controller Information" -Status "Export complete" -PercentComplete 100 -Completed
} else {
    Write-Progress -Activity "Retrieving Domain Controller Information" -Status "No domain controllers found" -PercentComplete 100 -Completed
    Write-Warning "No domain controllers were found."
}
