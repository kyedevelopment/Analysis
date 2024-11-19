Get-Process | ForEach-Object {
    $process = $_
    $modules = @()
    $highMemoryThreshold = 500MB
    $suspiciousLocations = @(
        "$env:TEMP",
        "$env:USERPROFILE\Downloads",
        "$env:APPDATA\Local\Temp"
    )
    
    try {
        $modules = $process.Modules | Where-Object { 
            ($_.FileName -notlike "C:\Windows\*") -and
            ($_.FileName -notlike "C:\Program Files*") -and
            (
                (Get-AuthenticodeSignature $_.FileName).Status -ne 'Valid' -or
                ($suspiciousLocations | ForEach-Object { $_.FileName -like "$_\*" })
            )
        } | Select-Object FileName, ModuleMemorySize
    } catch {
        Write-Warning "Access denied for process $($process.ProcessName) (PID: $($process.Id))"
    }

    [PSCustomObject]@{
        ProcessName = $process.ProcessName
        PID = $process.Id
        MemoryUsage = [math]::Round($process.WorkingSet64 / 1MB, 2)
        MemoryAlert = if ($process.WorkingSet64 -gt $highMemoryThreshold) { "HIGH" } else { "Normal" }
        CPUUsage = $process.CPU
        ThreadCount = $process.Threads.Count
        SuspiciousModules = $modules
        StartTime = $process.StartTime
        Path = $process.Path
    }
} | Sort-Object MemoryUsage -Descending | Format-Table -AutoSize -Wrap
