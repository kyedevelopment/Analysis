Get-Process | ForEach-Object {
    $process = $_
    try {
        $threads = $process.Threads.Count
        $handles = $process.HandleCount
        $modules = $process.Modules | Select-Object ModuleName
        $network = Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $process.Id }
        [PSCustomObject]@{
            ProcessName = $process.ProcessName
            PID         = $process.Id
            Threads     = $threads
            Handles     = $handles
            Modules     = $modules.ModuleName
            NetworkConnections = $network | Select-Object LocalAddress, RemoteAddress, State
            Status = "Running"
        }
    } catch [System.UnauthorizedAccessException] {
        Write-Warning "Access Denied: Process $($process.ProcessName) (PID: $($process.Id))"
        [PSCustomObject]@{
            ProcessName = $process.ProcessName
            PID = $process.Id
            Status = "Access Denied"
        }
    }
} | Out-GridView -Title "Process Behavior Analysis" -PassThru
