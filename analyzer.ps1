Clear-Host
$Host.UI.RawUI.WindowTitle = "Havoc"
$havocArt = @"
   _____ _                _                     ........                     ______ _           _           
  / ____| |              | |               .::...........:::.               |  ____(_)         | |          
 | |    | |__   ___  __ _| |_             :: .::---:.       ::             | |__   _ _ __   __| | ___ _ __ 
 | |    | '_ \ / _ \/ _` | __|           -: :*======::     . ::            |  __| | | '_ \ / _` |/ _ \ '__|
 | |____| | | |  __/ (_| | |_          .-. .*======-:.     :. .-.          | |    | | | | | (_| |  __/ |   
  \_____|_| |_|\___|\__,_|\__|        .- .-::...::..            -.         |_|    |_|_| |_|\__,_|\___|_|   
                                      -. ==::---::::..       .: .-                                         
                                      .-  .::. .::::..      ..  -.                                         
                                       -  :=-  --:          :: .-                                          
                                      .-  .-. -=: ..        ..  -.                                         
                                      -. -=: .:.:==-.        :. .-                                         
                                      -.  +*+==++-:..        :  .-                                         
                                   .::.  . :===-.::::::          .::.                                       
                                 ::. .:-.--  --.=... ..:      . ..  .::                                     
                                 ::  +++- ..   := .::. :.        .:  ::                                     
                             :...:-. :=.        =.... .:         .. .-:...:                                 
                             -:                  ::....                  :-                                 
                              -.  :=. :=.  :==  -=.  -- .====-  -====:  .-                                  
                               -  -#- =@:  +@@= :@+ -@- +@-:%% :@+:+@-  -                                   
                               -. :@+:+@: .%++%. +%:**  =@. +% :@-     .-                                   
                               -. :@+=*@: +%++@+ :@%@:  +@: *% :@= .-. .-                                   
                               -. :@- -%: *=  =*. =*+   -*++*+ .%*+*@- .-                                   
                               -. :+: .:  .    ..  ..   ......  .:-=+: .-                                   
                               -.  .                                .  .-                                   
                               -.    ..::::::::::::::::::::::::::..    .-                                   
                               -::::..                            ..::::-                                   
                               ..                                      ..                                   
"@
Write-Host $havocArt -ForegroundColor Red

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script needs to be run as Administrator. Please restart PowerShell as an Administrator and try again." -ForegroundColor Red
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}

function Show-MemoryAnomalyScan {
    Write-Output "Running Memory Anomaly Scanner..."
    $results = Get-Process | ForEach-Object {
        $process = $_
        $modules = @()
        try {
            $modules = $process.Modules | Where-Object { $_.FileName -notlike "C:\Windows\*" } | Select-Object FileName, ModuleMemorySize
        } catch {
            Write-Verbose "Error accessing process $($process.ProcessName): $($_.Exception.Message)"
        }
        [PSCustomObject]@{
            ProcessName        = $process.ProcessName
            PID                = $process.Id
            MemoryUsageMB      = [math]::Round($process.WorkingSet64 / 1MB, 2)
            SuspiciousModules  = $modules.FileName -join ", "
        }
    }
    $results | Out-GridView -Title "Memory Anomaly Scanner Results"
}

function Show-RegistryChangeMonitor {
    Write-Output "Running Registry Deletion Scanner..."
    
    $registryPaths = @() #need to add the registry paths here

    $deletionResults = @()
    
    foreach ($regPath in $registryPaths) {
        try {
            $key = Get-Item -Path $regPath.Path -ErrorAction Stop
            $currentTime = Get-Date
            $lastWriteTime = $key.LastWriteTime
            $timeDifference = $currentTime - $lastWriteTime
            
            $values = Get-ItemProperty -Path $regPath.Path
            
            $deletedEntries = $values.PSObject.Properties | 
                Where-Object { $_.Name -notlike "PS*" -and ($null -eq $_.Value -or $_.Value -eq "") }
            
            if ($deletedEntries -or $timeDifference.TotalMinutes -lt 60) {
                $deletionResults += [PSCustomObject]@{
                    Location = $regPath.Path
                    Description = $regPath.Description
                    LastModified = $lastWriteTime
                    MinutesAgo = [math]::Round($timeDifference.TotalMinutes, 2)
                    DeletedEntries = ($deletedEntries | ForEach-Object { $_.Name }) -join ", "
                    Status = if ($timeDifference.TotalMinutes -lt 60) { "Recent Changes" } else { "Deleted Entries Found" }
                }
            }
        }
        catch {
            Write-Warning "Unable to access: $($regPath.Path)"
        }
    }

    if ($deletionResults.Count -gt 0) {
        $deletionResults | Out-GridView -Title "Registry Deletion Detection Results"
    }
    else {
        Write-Host "No suspicious registry deletions or recent modifications detected." -ForegroundColor Green
    }
}

function Show-FileShadowingDetector {
    Write-Output "Running File Shadowing Detector..."
    Write-Output "This may take a couple of minutes..."
    $path = [Environment]::GetFolderPath('UserProfile')
    $results = @()

    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_
        if ($file.Attributes -match "Hidden") {
            $results += [PSCustomObject]@{
                FileName   = $file.FullName
                Attributes = $file.Attributes
            }
        }
        try {
            $ads = Get-Item -Path "$($file.FullName):*" -ErrorAction SilentlyContinue
            if ($ads) {
                $results += [PSCustomObject]@{
                    FileName = $file.FullName
                    ADS      = $ads.Name
                }
            }
        } catch {}
    }

    $results | Out-GridView -Title "File Shadowing Detector Results"
}

function Show-ProcessBehaviorAnalyzer {
    Write-Output "Running Process Behavior Analyzer..."
    $results = Get-Process | ForEach-Object {
        $process = $_
        try {
            $threads = $process.Threads.Count
            $handles = $process.HandleCount
            $network = Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $process.Id }
            [PSCustomObject]@{
                ProcessName         = $process.ProcessName
                PID                 = $process.Id
                Threads             = $threads
                Handles             = $handles
                NetworkConnections  = $network | Select-Object LocalAddress, RemoteAddress, State | Out-String
            }
        } catch [System.ComponentModel.Win32Exception] {
            Write-Verbose "Access denied for process $($process.ProcessName) with PID $($process.Id)"
        } catch {
            Write-Verbose "Error analyzing process $($process.ProcessName): $($_.Exception.Message)"
        }
    }
    $results | Out-GridView -Title "Process Behavior Analyzer Results"
}

function Show-MainMenu {
    while ($true) {
        Write-Host "`n=== Havoc Security Scanner ===" -ForegroundColor Cyan
        Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Blue
        Write-Host "║ [1] Memory Anomaly Scanner             ║" -ForegroundColor White
        Write-Host "║ [2] Registry Change Monitor            ║" -ForegroundColor White
        Write-Host "║ [3] File Shadowing Detector            ║" -ForegroundColor White
        Write-Host "║ [4] Process Behavior Analyzer          ║" -ForegroundColor White
        Write-Host "║ [5] Exit                               ║" -ForegroundColor White
        Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Blue
        
        $selection = Read-Host "`nSelect an option [1-5]"

        switch ($selection) {
            "1" { 
                Write-Host "`nLaunching Memory Scanner..." -ForegroundColor Green
                Show-MemoryAnomalyScan 
            }
            "2" { 
                Write-Host "`nLaunching Registry Monitor..." -ForegroundColor Green
                Show-RegistryChangeMonitor 
            }
            "3" { 
                Write-Host "`nLaunching File Detector..." -ForegroundColor Green
                Show-FileShadowingDetector 
            }
            "4" { 
                Write-Host "`nLaunching Process Analyzer..." -ForegroundColor Green
                Show-ProcessBehaviorAnalyzer 
            }
            "5" { 
                Write-Host "`nThank you for using Havoc Security Scanner" -ForegroundColor Cyan
                Start-Sleep -Seconds 1
                exit 
            }
            default { 
                Write-Host "`nInvalid selection. Please choose 1-5" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

Show-MainMenu
