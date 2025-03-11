# This script identifies PCI hardware devices, excluding bridges and infrastructure components

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

Write-Host @"
 ██░ ██  ▄▄▄    ██▒   █▓ ▒█████   ▄████▄  
▓██░ ██▒▒████▄ ▓██░   █▒▒██▒  ██▒▒██▀ ▀█  
▒██▀▀██░▒██  ▀█▄▓██  █▒░▒██░  ██▒▒▓█    ▄ 
░▓█ ░██ ░██▄▄▄▄██▒██ █░░▒██   ██░▒▓▓▄ ▄██▒
░▓█▒░██▓ ▓█   ▓██▒▒▀█░  ░ ████▓▒░▒ ▓███▀ ░
 ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▐░  ░ ▒░▒░▒░ ░ ░▒ ▒  ░
 ▒ ░▒░ ░  ▒   ▒▒ ░░ ░░    ░ ▒ ▒░   ░  ▒   
 ░  ░░ ░  ░   ▒     ░░  ░ ░ ░ ▒  ░        
 ░  ░  ░      ░  ░   ░      ░ ░  ░ ░      
                    ░            ░        
                                    -kye
"@ -ForegroundColor Red

Write-Host "Scanning for PCI hardware devices..." -ForegroundColor Yellow

$pciDevices = Get-WmiObject Win32_PnPEntity -Filter "PNPDeviceID LIKE 'PCI%'"
$hardwareDevices = @()

foreach ($device in $pciDevices) {
    $pciPath = $device.PNPDeviceID
    $segmentsPCI = $pciPath.Split('\')
    
    if ($segmentsPCI.Length -lt 2) { continue }
    
    $pciInfo = $segmentsPCI[1].Split('&')
    $vendorId = if ($pciInfo[0] -match "VEN_([0-9A-F]{4})") { $matches[1] } else { "UNKNOWN" }
    $deviceId = if ($pciInfo[1] -match "DEV_([0-9A-F]{4})") { $matches[1] } else { "UNKNOWN" }
    
    $shouldSkip = (
        $device.Name -like "*PCI-to-PCI*" -or
        $device.Name -like "*PCI Bridge*" -or
        $device.Name -like "*PCI Express Root*" -or
        $device.Name -like "*PCI Express Downstream*" -or
        $device.Name -like "*PCI Express Upstream*" -or
        $device.Name -like "*Host Bridge*" -or
        $device.Name -like "*SM Bus Controller*" -or
        $device.Name -like "*DRAM Controller*" -or
        $device.Name -like "*ISA Bridge*" -or
        $device.Class -eq "System" -and (
            $device.Name -like "*controller*" -or
            $device.Name -like "*bridge*"
        ) -or
        $device.Name -like "*PCI standard*"
    )
    
    if ($shouldSkip) {
        continue
    }
    
    $hardwareDevices += [PSCustomObject]@{
        Name = $device.Name
        VendorID = $vendorId
        DeviceID = $deviceId
        Class = $device.PNPClass
        PCIPath = $pciPath
    }
}

if ($hardwareDevices.Count -eq 0) {
    Write-Host "No PCI hardware devices detected." -ForegroundColor Yellow
}
else {
    Write-Host "Found $($hardwareDevices.Count) PCI hardware devices:" -ForegroundColor Green
    Write-Host "=========================================" -ForegroundColor Green
    
    foreach ($hardwareDevice in $hardwareDevices) {
        Write-Host "Name: $($hardwareDevice.Name)" -ForegroundColor Cyan
        Write-Host "Vendor:Device ID: $($hardwareDevice.VendorID):$($hardwareDevice.DeviceID)"
        Write-Host "Class: $($hardwareDevice.Class)"
        Write-Host "PCI Path: $($hardwareDevice.PCIPath)"
        Write-Host "----------------------------"
    }
}

Write-Host "Scan complete." -ForegroundColor Green
