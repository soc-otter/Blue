<#
.SYNOPSIS
Exports local user account information to CSV.

.DESCRIPTION
This script collects information about every local user account on the computer. Results are written to a CSV.

.NOTES
Requires PowerShell v5+.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Local_User_Accounts.ps1

.EXAMPLE
PS> .\Local_User_Accounts.ps1
#>

# Define the output directory and file
$OutputDirectory = "C:\BlueTeam"
$OutputFileName = "Local_User_Accounts.csv"
$OutputFilePath = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName

# Ensure the output directory exists
if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

Write-Progress -Activity "Collecting User Accounts" -Status "Retrieving user account information..."

$UserAccounts = @()

# Function to translate AccountType values
function Translate-AccountType {
    param (
        [int]$AccountTypeValue
    )

    $types = @()

    # Account type bits and their meanings
    if ($AccountTypeValue -band 0x0002) { $types += "Global Account" }
    if ($AccountTypeValue -band 0x0004) { $types += "Domain Account" }
    if ($AccountTypeValue -band 0x0008) { $types += "Local Account" }
    if ($AccountTypeValue -band 0x0010) { $types += "Local Guest Account" }
    if ($AccountTypeValue -band 0x0020) { $types += "Local Administrator Account" }
    if ($AccountTypeValue -band 0x0100) { $types += "Temp Duplicate Account" }
    if ($AccountTypeValue -band 0x0200) { $types += "Normal Account" }
    if ($AccountTypeValue -band 0x0800) { $types += "Interdomain Trust Account" }
    if ($AccountTypeValue -band 0x1000) { $types += "Workstation Trust Account" }
    if ($AccountTypeValue -band 0x2000) { $types += "Server Trust Account" }
    if ($AccountTypeValue -band 0x800000) { $types += "Security Enabled Global Group" }
    if ($AccountTypeValue -band 0x10000000) { $types += "Security Enabled Universal Group" }
    if ($AccountTypeValue -band 0x20000000) { $types += "Security Enabled Local Group" }

    if ($types.Count -gt 0) {
        return $types -join ", "
    } else {
        return "Unknown ($AccountTypeValue)"
    }
}

# Function to convert WMI CIM_DATETIME format to a readable DateTime object
function Convert-CIMDateTime {
    param (
        [string]$CIMDateTime
    )

    if ([string]::IsNullOrEmpty($CIMDateTime) -or $CIMDateTime -eq '-' -or $CIMDateTime -eq $null) {
        return "-"
    } else {
        try {
            $dateTime = [Management.ManagementDateTimeConverter]::ToDateTime($CIMDateTime)
            # Ensure the conversion does not result in an un-representable DateTime
            if ($dateTime.Year -eq 1) {
                return "-"
            } else {
                return $dateTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
        } catch {
            return "-"
        }
    }
}

# Define the properties to collect and their order
$PropertyNames = @(
    'UserName',
    'FullName',
    'SID',
    'Domain',
    'NumberOfLogons',
    'Status',
    'GroupMembership',
    'AccountTypeValue',
    'AccountType',
    'Disabled',
    'Lockout',
    'PasswordRequired',
    'PasswordChangeable',
    'PasswordExpires',
    'PasswordExpiresInDays',
    'PasswordAge',
    'BadPasswordCount',
    'LastLogon',
    'LastLogoff',
    'InstallDate',
    'HomeDirectory',
    'ProfilePath',
    'ScriptPath',
    'Description'
)

# Retrieve all network login profiles in one call
$LoginProfiles = Get-WmiObject -Class Win32_NetworkLoginProfile -ErrorAction SilentlyContinue

# Use Get-WmiObject to retrieve local user accounts
$Users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"

foreach ($User in $Users) {
    # Prepare a hashtable to collect properties
    $UserInfo = @{}

    # Get properties
    $UserName           = if ($User.Name) { $User.Name } else { "-" }
    $SID                = if ($User.SID) { $User.SID } else { "-" }
    $Domain             = if ($User.Domain) { $User.Domain } else { "-" }
    $FullName           = if ($User.FullName) { $User.FullName } else { "-" }
    $Description        = if ($User.Description) { $User.Description } else { "-" }
    $Disabled           = if ($User.Disabled -ne $null) { $User.Disabled } else { "-" }
    $Lockout            = if ($User.Lockout -ne $null) { $User.Lockout } else { "-" }
    $PasswordRequired   = if ($User.PasswordRequired -ne $null) { $User.PasswordRequired } else { "-" }
    $PasswordChangeable = if ($User.PasswordChangeable -ne $null) { $User.PasswordChangeable } else { "-" }
    $PasswordExpires    = if ($User.PasswordExpires -ne $null) { $User.PasswordExpires } else { "-" }
    $InstallDate        = Convert-CIMDateTime $User.InstallDate
    $Status             = if ($User.Status) { $User.Status } else { "-" }
    $AccountTypeValue   = if ($User.AccountType -ne $null) { $User.AccountType } else { "-" }
    $AccountType        = if ($User.AccountType -ne $null) { Translate-AccountType $User.AccountType } else { "-" }

    # Get groups
    $Groups = Get-WmiObject -Query "Associators of {Win32_UserAccount.Domain='$($User.Domain)',Name='$($User.Name)'} Where AssocClass=Win32_GroupUser Role=PartComponent" -ErrorAction SilentlyContinue | Select -ExpandProperty Name
    $GroupMembership = if ($Groups) { $Groups -join ";" } else { "-" }

    # Get profile
    $FullyQualifiedUserName = "$Domain\$UserName"
    $LoginProfile = $LoginProfiles | Where-Object { $_.Name -eq $FullyQualifiedUserName }

    if ($LoginProfile) {
        $LastLogon = Convert-CIMDateTime $LoginProfile.LastLogon
        $LastLogoff = Convert-CIMDateTime $LoginProfile.LastLogoff
        $BadPasswordCount = if ($LoginProfile.BadPasswordCount -ne $null) { $LoginProfile.BadPasswordCount } else { "-" }
        
        # Retrieve NumberOfLogons
        $NumberOfLogons = if ([string]::IsNullOrWhiteSpace($LoginProfile.NumberOfLogons) -or $LoginProfile.NumberOfLogons -eq $null) {
            "-"
        } else {
            $LoginProfile.NumberOfLogons
        }

        $HomeDirectory = if ($LoginProfile.HomeDirectory -ne $null -and $LoginProfile.HomeDirectory.Trim() -ne '') { $LoginProfile.HomeDirectory.Trim() } else { "-" }
        $ScriptPath = if ($LoginProfile.ScriptPath -ne $null -and $LoginProfile.ScriptPath.Trim() -ne '') { $LoginProfile.ScriptPath.Trim() } else { "-" }
        $ProfilePath = if ($LoginProfile.Profile -ne $null -and $LoginProfile.Profile.Trim() -ne '') { $LoginProfile.Profile.Trim() } else { "-" }
        
        # Convert PasswordAge and PasswordExpires using CIM_DATETIME conversion
        $PasswordAge = Convert-CIMDateTime $LoginProfile.PasswordAge

        # Calculate PasswordExpiresInDays if possible
        if ($LoginProfile.PasswordExpires -ne $null -and $LoginProfile.PasswordAge -ne $null) {
            try {
                $maxPasswordAge = [Management.ManagementDateTimeConverter]::ToDateTime($LoginProfile.PasswordExpires)
                $passwordAge = [Management.ManagementDateTimeConverter]::ToDateTime($LoginProfile.PasswordAge)
                $expiresInDays = ($maxPasswordAge - $passwordAge).TotalDays
                $PasswordExpiresInDays = [Math]::Round($expiresInDays, 2)
            } catch {
                $PasswordExpiresInDays = "-"
            }
        } else {
            $PasswordExpiresInDays = "-"
        }
    } else {
        $LastLogon = "-"
        $LastLogoff = "-"
        $BadPasswordCount = "-"
        $NumberOfLogons = "-"
        $HomeDirectory = "-"
        $ScriptPath = "-"
        $ProfilePath = "-"
        $PasswordAge = "-"
        $PasswordExpiresInDays = "-"
    }

    # Collect properties into hashtable
    $UserInfo['UserName']              = $UserName
    $UserInfo['FullName']              = $FullName
    $UserInfo['SID']                   = $SID
    $UserInfo['Domain']                = $Domain
    $UserInfo['NumberOfLogons']        = $NumberOfLogons
    $UserInfo['Status']                = $Status
    $UserInfo['GroupMembership']       = $GroupMembership
    $UserInfo['AccountTypeValue']      = $AccountTypeValue
    $UserInfo['AccountType']           = $AccountType
    $UserInfo['Disabled']              = $Disabled
    $UserInfo['Lockout']               = $Lockout
    $UserInfo['PasswordRequired']      = $PasswordRequired
    $UserInfo['PasswordChangeable']    = $PasswordChangeable
    $UserInfo['PasswordExpires']       = $PasswordExpires
    $UserInfo['PasswordExpiresInDays'] = $PasswordExpiresInDays
    $UserInfo['PasswordAge']           = $PasswordAge
    $UserInfo['BadPasswordCount']      = $BadPasswordCount
    $UserInfo['LastLogon']             = $LastLogon
    $UserInfo['LastLogoff']            = $LastLogoff
    $UserInfo['InstallDate']           = $InstallDate
    $UserInfo['HomeDirectory']         = $HomeDirectory
    $UserInfo['ProfilePath']           = $ProfilePath
    $UserInfo['ScriptPath']            = $ScriptPath
    $UserInfo['Description']           = $Description

    # Add to the collection
    $UserAccounts += New-Object PSObject -Property $UserInfo
}

if ($UserAccounts) {
    Write-Progress -Activity "Exporting Data" -Status "Writing to CSV..."

    # Reorder the properties
    $UserAccountsOrdered = $UserAccounts | Select-Object $PropertyNames

    # Export to CSV
    $UserAccountsOrdered | Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8

    Write-Progress -Activity "Collection Complete" -Status "Data exported to CSV" -Completed
} else {
    Write-Warning "No user account information found to export."
    Write-Progress -Activity "Collection Complete" -Status "No data to export" -Completed
}
