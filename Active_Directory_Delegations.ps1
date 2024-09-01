<#
.SYNOPSIS
Retrieves information on Active Directory computer objects and their delegation settings for the current domain.

.DESCRIPTION
This script enumerates Active Directory computer objects to capture their delegation settings, identifying both unconstrained and constrained delegation. It exports details such as computer names, delegation types, allowed services, and other relevant properties to a CSV file. This information identifies weak security configurations in AD environments, such as privilege escalation opportunities, and helps assess which systems are configured securely (hardened).

Active Directory supports two types of Kerberos delegation: constrained and unconstrained, which differ in their control over how services can impersonate users. Unconstrained delegation is configured at the host level, allowing any service on that host to impersonate any user who authenticates to it and access any network resource on their behalf. Consider a scenario where Bob's server is configured for unconstrained delegation, and an attacker compromises Bob's account. If Alice, who is a domain admin, has previously connected to Bob's server, the attacker's access to Bob's compromised server allows them to impersonate Alice by using her cached credentials. With Alice's domain admin privileges, the attacker gains full control over the Active Directory environment, enabling them to manage or modify any domain resources, create new administrative accounts, disable security tools, and access sensitive data throughout the network. In contrast, constrained delegation is configured at the service account level and restricts which specific services can impersonate a user and to which other services they can delegate credentials. If constrained delegation were in place, even if Bob’s server were compromised, the attacker would only be able to use Alice’s credentials for predefined services, significantly limiting the potential damage. Unconstrained delegation poses a high risk because it enables unrestricted impersonation of high-privilege accounts like Alice’s, whereas constrained delegation reduces such risks by enforcing stricter controls.

.NOTES
Requires PowerShell v5 and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Active_Directory_Delegations.ps1

.EXAMPLE
PS> .\Active_Directory_Delegations.ps1
#>

# Define the output directory and file
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory "Active_Directory_Delegations.csv"

# Ensure output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Check if Active Directory module is available and import it
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "ERROR: ActiveDirectory module not found. Please install RSAT tools to use this script." -ForegroundColor Red
    Write-Host "To install RSAT on Windows 10/11, run the following command in PowerShell as an Administrator:" -ForegroundColor Yellow
    Write-Host "Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'" -ForegroundColor Yellow
    exit
}
Import-Module -Name ActiveDirectory

# Exclusion list for approved computers
$excludeComputers = @{
    "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy" = $true
    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" = $true
}

# ArrayList for better performance
$results = New-Object System.Collections.ArrayList

# Initialize variables
$processedCount = 0

# Process each computer object
Get-ADComputer -Filter * -Properties Name, TrustedForDelegation, 'msDS-AllowedToDelegateTo', ObjectClass, LastLogonDate, SID, DistinguishedName, ObjectGUID, OperatingSystem, OperatingSystemVersion, DNSHostName, Location, Description | ForEach-Object {
    $computer = $_
    $processedCount++

    # Update progress every 100 computers
    if ($processedCount % 100 -eq 0) {
        Write-Progress -Activity "Processing Active Directory Computers" -Status "Hosts Processed: $processedCount | Delegations found: $($results.Count)"
    }

    if (-not $excludeComputers.ContainsKey($computer.Name)) {
        $delegationType = "-"
        $allowedToDelegateTo = "-"
        $hardened = "-"

        if ($computer.TrustedForDelegation) {
            $delegationType = "Unconstrained"
            $hardened = "FALSE"
        } elseif ($computer.'msDS-AllowedToDelegateTo') {
            $delegationType = "Constrained"
            $allowedToDelegateTo = $computer.'msDS-AllowedToDelegateTo' -join ","
            $hardened = "TRUE"
        }

        if ($delegationType -ne "-") {
            $null = $results.Add([PSCustomObject]@{
                ComputerName           = $computer.Name
                DNSHostName            = if ($computer.DNSHostName) { $computer.DNSHostName } else { "-" }
                DelegationType         = $delegationType
                Hardened               = $hardened
                AllowedToDelegateTo    = $allowedToDelegateTo
                OperatingSystem        = if ($computer.OperatingSystem) { $computer.OperatingSystem } else { "-" }
                OperatingSystemVersion = if ($computer.OperatingSystemVersion) { $computer.OperatingSystemVersion } else { "-" }
                Description            = if ($computer.Description) { $computer.Description } else { "-" }
                ObjectClass            = $computer.ObjectClass
                LastLogonDate          = if ($computer.LastLogonDate) { $computer.LastLogonDate } else { "-" }
                SID                    = if ($computer.SID) { $computer.SID.ToString() } else { "-" }
                ObjectGUID             = if ($computer.ObjectGUID) { $computer.ObjectGUID.ToString() } else { "-" }
                DistinguishedName      = if ($computer.DistinguishedName) { $computer.DistinguishedName } else { "-" }
                Location               = if ($computer.Location) { $computer.Location } else { "-" }
            })
        }
    }
}

# Export CSV
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Progress -Activity "Exporting Results" -Status "Processed: $processedCount | With Delegation: $($results.Count)" -Completed
} else {
    Write-Progress -Activity "Script Completed" -Status "Processed: $processedCount | No relevant delegations found" -Completed
}
