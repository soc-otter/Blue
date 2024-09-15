<#
.SYNOPSIS
Gathers information about disk partitions.

.DESCRIPTION
This script identifies disk partitions and provides information about each partition, including size, type, GPT information, and various status flags. Results are written to a CSV.

.NOTES
Requires PowerShell v5+.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Partitions.ps1

.EXAMPLE
PS> .\Partitions.ps1
#>

# Set outputs
$outputPath = "C:\BlueTeam"
$outputFile = Join-Path $outputPath "Partitions.csv"

function Get-FormattedSize {
    param (
        [long]$SizeInBytes
    )
    $sizes = @('Bytes', 'KB', 'MB', 'GB', 'TB', 'PB')
    $index = 0
    $size = $SizeInBytes

    while ($size -ge 1024 -and $index -lt ($sizes.Count - 1)) {
        $size = $size / 1024
        $index++
    }

    return "{0:N2} {1}" -f $size, $sizes[$index]
}

function Get-GptTypeName {
    param (
        [string]$GptType
    )
    $gptTypes = @{
        '{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}' = 'Basic data partition'
        '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' = 'EFI System partition'
        '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}' = 'Microsoft Reserved Partition (MSR)'
        '{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}' = 'Windows Recovery Environment'
        '{5808C8AA-7E8F-42E0-85D2-E1E90434CFB3}' = 'LDM metadata partition'
        '{AF9B60A0-1431-4F62-BC68-3311714A69AD}' = 'LDM data partition'
        '{D3BFE2DE-3DAF-11DF-BA40-E3A556D89593}' = 'Intel Fast Flash (iFFS) partition'
        '{F4019732-066E-4E12-8273-346C5641494F}' = 'Sony boot partition'
        '{BFBFAFE7-A34F-448A-9A5B-6213EB736C22}' = 'Lenovo boot partition'
        '{E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D}' = 'Storage Spaces partition'
        '{558D43C5-A1AC-43C0-AAC8-D1472B2923D1}' = 'Storage Replica partition'
        '{37AFFC90-EF7D-4E96-91C3-2D7AE055B174}' = 'IBM GPFS partition'
        '{21686148-6449-6E6F-744E-656564454649}' = 'BIOS boot partition'
        '{024DEE41-33E7-11D3-9D69-0008C781F39F}' = 'MBR partition scheme'
        '{00000000-0000-0000-0000-000000000000}' = 'Unused entry'
    }
    
    if ($gptTypes.ContainsKey($GptType)) {
        return $gptTypes[$GptType]
    } else {
        return "Unknown"
    }
}

function Get-AllPartitions {
    Get-Partition | ForEach-Object {
        [PSCustomObject]@{
            DiskNumber = $_.DiskNumber
            PartitionNumber = $_.PartitionNumber
            Size = Get-FormattedSize -SizeInBytes $_.Size
            DriveLetter = if ($_.DriveLetter) { $_.DriveLetter } else { "-" }
            Type = if ($_.Type) { $_.Type } else { "-" }
            GptType = if ($_.GptType) { $_.GptType } else { "-" }
            GptTypeName = if ($_.GptType) { Get-GptTypeName $_.GptType } else { "-" }
            MbrType = if ($_.MbrType) { $_.MbrType } else { "-" }
            IsActive = if ($_.IsActive) { "True" } else { "False" }
            IsBoot = if ($_.IsBoot) { "True" } else { "False" }
            IsHidden = if ($_.IsHidden) { "True" } else { "False" }
            IsSystem = if ($_.IsSystem) { "True" } else { "False" }
            IsReadOnly = if ($_.IsReadOnly -eq $true) { "True" } elseif ($_.IsReadOnly -eq $false) { "False" } else { "-" }
            IsOffline = if ($_.IsOffline -eq $true) { "True" } elseif ($_.IsOffline -eq $false) { "False" } else { "-" }
            IsShadowCopy = if ($_.IsShadowCopy -eq $true) { "True" } elseif ($_.IsShadowCopy -eq $false) { "False" } else { "-" }
            NoDefaultDriveLetter = if ($_.NoDefaultDriveLetter) { "True" } else { "False" }
            Offset = $_.Offset
            AccessPaths = if ($_.AccessPaths) { $_.AccessPaths -join '; ' } else { "-" }
            UniqueId = if ($_.UniqueId) { $_.UniqueId } else { "-" }
            Guid = if ($_.Guid) { $_.Guid } else { "-" }
            OperationalStatus = if ($_.OperationalStatus) { $_.OperationalStatus } else { "-" }
            TransitionState = if ($_.TransitionState) { $_.TransitionState } else { "-" }
        }
    }
}

$allPartitions = Get-AllPartitions

if ($allPartitions) {
    if (-not (Test-Path -Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    }
    $allPartitions | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Progress -Activity "Documenting all partitions" -Status "Complete" -Completed
} else {
    Write-Warning "No partitions found on this system."
}
