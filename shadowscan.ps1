$findings = [System.Collections.ArrayList]@()

$path = "C:\"
Get-ChildItem -Path $path -Recurse -Force | ForEach-Object {
    $file = $_
    
    if ($file.Attributes -match "Hidden") {
        $findings.Add([PSCustomObject]@{
            Type = "Hidden File"
            FileName = $file.FullName
            Size = $file.Length
            CreationTime = $file.CreationTime
            LastModified = $file.LastWriteTime
            Attributes = $file.Attributes
            Owner = (Get-Acl $file.FullName).Owner
            ADS = "N/A"
        }) | Out-Null
    }

    try {
        $streams = Get-Item -Path "$($file.FullName):*" -Stream * -ErrorAction SilentlyContinue
        $streams | Where-Object { $_.Stream -ne ':$DATA' } | ForEach-Object {
            $findings.Add([PSCustomObject]@{
                Type = "Alternate Data Stream"
                FileName = $file.FullName
                Size = $_.Length
                CreationTime = $file.CreationTime
                LastModified = $file.LastWriteTime
                Attributes = $file.Attributes
                Owner = (Get-Acl $file.FullName).Owner
                ADS = $_.Stream
            }) | Out-Null
        }
    } catch {}
}

$findings | Out-GridView -Title "Hidden Files and Alternate Data Streams Scanner" -PassThru
