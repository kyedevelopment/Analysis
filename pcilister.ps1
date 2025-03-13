# This script displays all PCI devices

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

Write-Host @"
  _    _                      
 | |  | |                     
 | |__| | __ ___   _____   ___ 
 |  __  |/ _' \ \ / / _ \ / __|
 | |  | | (_| |\ V / (_) | (__ 
 |_|  |_|\__,_| \_/ \___/ \___|
                         -kye
"@ -ForegroundColor Red

Write-Host "Scanning for PCI hardware devices..." -ForegroundColor Yellow

$pciDevices = Get-WmiObject Win32_PnPEntity -Filter "PNPDeviceID LIKE 'PCI%'"
$allDevices = @()

foreach ($device in $pciDevices) {
    $pciPath = $device.PNPDeviceID
    $segmentsPCI = $pciPath.Split('\')
    
    if ($segmentsPCI.Length -lt 2) { continue }
    
    $pciInfo = $segmentsPCI[1].Split('&')
    
    $vendorId = if ($pciInfo.Length -gt 0) {
        if ($pciInfo[0] -match "VEN_([0-9A-F]{4})") {
            $matches[1]
        } elseif ($pciInfo[0] -match "V([0-9A-F]{4})") {
            $matches[1]
        } elseif ($pciInfo[0] -match "^([0-9A-F]{4})$") {
            $matches[1]
        } elseif ($pciInfo[0] -match "VENDOR([0-9A-F]{4})") {
            $matches[1]
        } elseif ($pciInfo[0] -match "([0-9A-F]{4})h") {
            $matches[1]
        } else {
            "UNKNOWN"
        }
    } else {
        "UNKNOWN"
    }
    
    $deviceId = if ($pciInfo.Length -gt 1) {
        if ($pciInfo[1] -match "DEV_([0-9A-F]{4})") {
            $matches[1]
        } elseif ($pciInfo[1] -match "D([0-9A-F]{4})") {
            $matches[1]
        } elseif ($pciInfo[1] -match "^([0-9A-F]{4})$") {
            $matches[1]
        } elseif ($pciInfo[1] -match "DEVICE([0-9A-F]{4})") {
            $matches[1]
        } elseif ($pciInfo[1] -match "([0-9A-F]{4})h") {
            $matches[1]
        } else {
            "UNKNOWN"
        }
    } else {
        "UNKNOWN"
    }
    
    if ($vendorId -eq "UNKNOWN" -or $deviceId -eq "UNKNOWN") {
        $fullString = $segmentsPCI[1]
        
        if ($vendorId -eq "UNKNOWN" -and $fullString -match "VEN_([0-9A-F]{4})") {
            $vendorId = $matches[1]
        }
        
        if ($deviceId -eq "UNKNOWN" -and $fullString -match "DEV_([0-9A-F]{4})") {
            $deviceId = $matches[1]
        }
    }
    
    $allDevices += [PSCustomObject]@{
        Name = $device.Name
        VendorID = $vendorId
        DeviceID = $deviceId
        Class = $device.PNPClass
        PCIPath = $pciPath
    }
}


if ($allDevices.Count -eq 0) {
    Write-Host "No PCI devices detected." -ForegroundColor Red
}
else {
    Write-Host "Found $($allDevices.Count) PCI devices. Displaying results..." -ForegroundColor Green
    
    $allDevices | Out-GridView -Title "Havoc | PCI Devices" -OutputMode None
}

Write-Host "Scan complete." -ForegroundColor Green
