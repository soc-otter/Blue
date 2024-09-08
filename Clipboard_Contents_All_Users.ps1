<#

.SYNOPSIS
Captures and saves clipboard contents from all logged-in users.

.DESCRIPTION
This script captures clipboard content from all logged-in users by creating and immediately triggering scheduled tasks that run under each user's context. The captured content is saved to individual text files named after the respective user in the output directory. This is useful in investigations to determine what information a potentially compromised user had in their clipboard at the time of the incident. The collected data provides context for understanding user activities during an investigation. The script ensures the output directory exists and cleans up the tasks after they run.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Clipboard_Contents_All_Users.ps1

.EXAMPLE
PS> .\Clipboard_Contents_All_Users.ps1

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

# Function to create a task for clipboard capture
function Create-CaptureTask {
    param (
        [string]$username,
        [string]$filePath
    )

    $taskName = "GetClipboardContents_$($username -replace '[^a-zA-Z0-9]', '_')"
    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `"Add-Type -AssemblyName System.Windows.Forms; `$content = [System.Windows.Forms.Clipboard]::GetText(); if (`$content) { `$content | Out-File -FilePath '$filePath' -Encoding UTF8 }`""
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
    $filePath = Join-Path $outputDirectory "${username}_Clipboard_Contents.txt"

    # Only add tasks that were successfully created
    if (Create-CaptureTask -username $username -filePath $filePath) {
        $tasksCreated += "GetClipboardContents_$($username -replace '[^a-zA-Z0-9]', '_')"
    }
}

# Create a task to capture SYSTEM clipboard
$systemFilePath = Join-Path $outputDirectory "SYSTEM_Clipboard_Contents.txt"
if (Create-CaptureTask -username "SYSTEM" -filePath $systemFilePath) {
    $tasksCreated += "GetClipboardContents_SYSTEM"
}

# Start tasks only if they were successfully created
foreach ($taskName in $tasksCreated) {
    if ($taskName -and (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        Start-ScheduledTask -TaskName $taskName 2> $null
    }
}

# Wait for tasks to complete
$timeout = [DateTime]::Now.AddSeconds(5)
while ([DateTime]::Now -lt $timeout) {
    $pendingTasks = Get-ScheduledTask | Where-Object { $tasksCreated -contains $_.TaskName -and $_.State -eq 'Running' } | Out-Null
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
