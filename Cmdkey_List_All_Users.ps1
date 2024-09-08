<#

.SYNOPSIS
Captures and saves the output of `cmdkey /list` from all logged-in users.

.DESCRIPTION
This script captures the output of `cmdkey /list` from all logged-in users by creating and immediately triggering scheduled tasks that run under each user's context. The captured output is saved to individual text files named after the respective user in the output directory. This is useful for investigations to determine what credentials are stored in the Credential Manager at the time of an incident. The script ensures the output directory exists and cleans up the tasks after they run.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Cmdkey_List_All_Users.ps1

.EXAMPLE
PS> .\Cmdkey_List_All_Users.ps1

#>

# Define the output directory
$outputDirectory = 'C:\BlueTeam'
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Get all user profiles
$userProfiles = Get-ChildItem 'C:\Users' | Where-Object { $_.PSIsContainer -and $_.Name -notmatch '^(Default|Public|All Users|Default User|systemprofile)$' }

$createdFiles = @()
$tasksCreated = @()

# Function to create a task for capturing cmdkey output
function Create-CaptureTask {
    param (
        [string]$username,
        [string]$filePath
    )

    $taskName = "GetCmdKeyList_$($username -replace '[^a-zA-Z0-9]', '_')"
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c cmdkey /list > `"$filePath`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(1)

    if ($username -eq "SYSTEM") {
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    } else {
        $principal = New-ScheduledTaskPrincipal -UserId $username -LogonType Interactive -RunLevel Highest
    }

    # Attempt to register the scheduled task and capture errors
    $output = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force 2>&1
    if ($output -like "*No mapping between account names and security IDs was done*") {
        Write-Host "Error for user '$username'. Register-ScheduledTask : No mapping between account names and security IDs was done. Is this an orphaned account?" -ForegroundColor Yellow
        return $false
    }

    $tasksCreated += $taskName
    $createdFiles += $filePath
    return $true
}

# Loop through each user profile and attempt to create tasks
foreach ($profile in $userProfiles) {
    $username = $profile.Name
    $filePath = Join-Path $outputDirectory "${username}_Cmdkey_List.txt"

    # Only add tasks that were successfully created
    if (Create-CaptureTask -username $username -filePath $filePath) {
        $tasksCreated += "GetCmdKeyList_$($username -replace '[^a-zA-Z0-9]', '_')"
    }
}

# Create a task to capture SYSTEM cmdkey output
$systemFilePath = Join-Path $outputDirectory "SYSTEM_Cmdkey_List.txt"
if (Create-CaptureTask -username "SYSTEM" -filePath $systemFilePath) {
    $tasksCreated += "GetCmdKeyList_SYSTEM"
}

# Start tasks only if they were successfully created
foreach ($taskName in $tasksCreated) {
    if ($taskName -and (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        Start-ScheduledTask -TaskName $taskName 2> $null
    }
}

# Wait for tasks to complete
$timeout = [DateTime]::Now.AddSeconds(10)
while ([DateTime]::Now -lt $timeout) {
    $pendingTasks = Get-ScheduledTask | Where-Object { $tasksCreated -contains $_.TaskName -and $_.State -eq 'Running' }
    if ($pendingTasks.Count -eq 0) {
        break
    }
    Start-Sleep -Milliseconds 500
}

# Check captured files and clean up tasks
foreach ($filePath in $createdFiles) {
    if (Test-Path $filePath) {
        $fileContent = Get-Content -Path $filePath -Raw
        if ([string]::IsNullOrWhiteSpace($fileContent)) {
            Remove-Item -Path $filePath -Force
        }
    } else {
        Write-Host "Failed to create or access file: $filePath" -ForegroundColor Yellow
    }
}

foreach ($taskName in $tasksCreated) {
    if ($taskName -and (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}
