import mmap
import os
import struct
import datetime
import binascii
import ctypes
import re
from ctypes import wintypes, windll, Structure, sizeof, POINTER, pointer

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID),
        ("dwActiveProcessorMask", wintypes.LPVOID),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]

def create_memory_dump(output_file):
    kernel32 = windll.kernel32
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEMORY_CHUNK_SIZE = 4096 * 64
    MAX_DUMP_SIZE_PER_PROCESS = 50 * 1024 * 1024
    
    print(f"[+] Starting memory capture...")
    
    with open(output_file, 'wb') as dump_file:
        cmd_output = os.popen('wmic process get caption,processid,commandline,workingsetsize /format:csv').read()
        
        for line in cmd_output.splitlines():
            if ',' not in line or 'Caption' in line:
                continue
                
            try:
                parts = line.split(',')
                process_name = parts[1].lower()
                process_id = int(parts[-2]) if parts[-2].isdigit() else 0
                working_set = int(parts[-1]) if parts[-1].isdigit() else 0
                command_line = parts[2] if len(parts) > 3 else ""
                
                if working_set < 1000000: 
                    continue
                
                print(f"\n[+] Processing: {process_name} (PID: {process_id})")
                print(f"    Memory Usage: {working_set / 1024 / 1024:.1f}MB")
                print(f"    Command: {command_line}")
                
                process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
                if process_handle:
                    try:
                        header = f"PROCESS_START|{process_name}|{process_id}|{working_set}\n".encode()
                        dump_file.write(header)
                        
                        bytes_read_total = 0
                        current_address = 0x10000
                        
                        while bytes_read_total < MAX_DUMP_SIZE_PER_PROCESS:
                            read_buffer = ctypes.create_string_buffer(MEMORY_CHUNK_SIZE)
                            bytes_read = ctypes.c_size_t()
                            
                            if kernel32.ReadProcessMemory(
                                process_handle,
                                ctypes.c_void_p(current_address),
                                read_buffer,
                                MEMORY_CHUNK_SIZE,
                                ctypes.byref(bytes_read)
                            ):
                                if bytes_read.value > 0:
                                    dump_file.write(read_buffer.raw[:bytes_read.value])
                                    bytes_read_total += bytes_read.value
                            
                            current_address += MEMORY_CHUNK_SIZE
                            if current_address > 0x7FFFFFFF:
                                break
                        
                        dump_file.write(b"PROCESS_END\n")
                        print(f"    [+] Captured {bytes_read_total / 1024 / 1024:.1f}MB")
                        
                    finally:
                        kernel32.CloseHandle(process_handle)
                        
            except Exception as e:
                print(f"    [-] Error: {str(e)}")
                continue
    
    return True

def scan_memory_for_processes(dump_file):
    process_signatures = {
        b'chrome.exe': 'Google Chrome',
        b'firefox.exe': 'Mozilla Firefox',
        b'explorer.exe': 'Windows Explorer',
        b'notepad.exe': 'Notepad',
        b'cmd.exe': 'Command Prompt',
        b'powershell.exe': 'PowerShell',
        b'outlook.exe': 'Microsoft Outlook',
        b'teams.exe': 'Microsoft Teams',
        b'runas.exe': 'Elevated Permission Process',
        b'consent.exe': 'UAC Prompt',
        b'sudo': 'Elevated Command',
        b'Administrator': 'Admin Context'
    }
    
    found_processes = {}
    
    try:
        with open(dump_file, 'rb') as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            
            for signature, process_name in process_signatures.items():
                position = 0
                while True:
                    try:
                        position = mm.find(signature, position)
                        if position == -1:
                            break
                        
                        context = mm[max(0, position-100):min(position+100, mm.size())]
                        found_processes[process_name] = {
                            'offset': hex(position),
                            'surrounding_data': binascii.hexlify(context).decode()
                        }
                        position += 1
                    except:
                        break
                        
            mm.close()
    except Exception as e:
        print(f"Memory scanning encountered an issue: {str(e)}")
    
    return found_processes

def analyze_applications_and_permissions(dump_file):
    found_items = {
        'applications': [],
        'elevated_perms': [],
        'hardware': []
    }
    
    process_signatures = {
        b'chrome.exe': 'Google Chrome',
        b'firefox.exe': 'Mozilla Firefox',
        b'explorer.exe': 'Windows Explorer',
        b'notepad.exe': 'Notepad',
        b'cmd.exe': 'Command Prompt',
        b'powershell.exe': 'PowerShell',
        b'outlook.exe': 'Microsoft Outlook',
        b'teams.exe': 'Microsoft Teams',
        b'winlogon.exe': 'Windows Logon',
        b'svchost.exe': 'Service Host',
        b'csrss.exe': 'Client Server Runtime',
        b'lsass.exe': 'Security Subsystem',
        b'taskmgr.exe': 'Task Manager',
        b'regedit.exe': 'Registry Editor',
        b'mmc.exe': 'Management Console',
        b'services.exe': 'Service Control Manager',
        b'spoolsv.exe': 'Print Spooler',
        b'wininit.exe': 'Windows Start-Up',
        b'smss.exe': 'Session Manager',
        b'conhost.exe': 'Console Host',
        b'dllhost.exe': 'COM Surrogate',
        b'taskhost.exe': 'Task Host'
    }
    
    elevation_signatures = {
        b'UAC.exe': 'User Account Control',
        b'runas': 'Run As Administrator',
        b'SeDebugPrivilege': 'Debug Privilege',
        b'NT AUTHORITY\\SYSTEM': 'System Authority',
        b'Administrators': 'Admin Group',
        b'sudo': 'Elevated Command',
        b'TrustedInstaller': 'Windows Trusted Installer',
        b'SeBackupPrivilege': 'Backup Privilege',
        b'SeRestorePrivilege': 'Restore Privilege',
        b'SeTakeOwnershipPrivilege': 'Take Ownership Privilege',
        b'SeLoadDriverPrivilege': 'Load Driver Privilege',
        b'SeSecurityPrivilege': 'Security Privilege'
    }
    
    hardware_signatures = [
        b'USB\\VID_', b'USB\\PID_',
        b'PCI\\VEN_', b'PCI\\DEV_',
        b'USBSTOR\\', b'SCSI\\',
        b'STORAGE\\VOLUME',
        b'HID\\', b'DISPLAY\\',
        b'ACPI\\', b'ROOT\\',
        b'IDE\\', b'HDAUDIO\\',
        b'PCI_IDE\\', b'STORAGE\\',
        b'USBPRINT\\', b'MEDIA\\',
        b'SCSI\\CdRom', b'USBHUB\\',
        b'USB\\ROOT_HUB'
    ]
    
    try:
        with open(dump_file, 'rb') as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            
            for sig, name in process_signatures.items():
                pos = 0
                while True:
                    pos = mm.find(sig, pos)
                    if pos == -1:
                        break
                    found_items['applications'].append(name)
                    pos += len(sig)
            
            for sig, name in elevation_signatures.items():
                pos = 0
                while True:
                    pos = mm.find(sig, pos)
                    if pos == -1:
                        break
                    found_items['elevated_perms'].append(name)
                    pos += len(sig)
            
            for sig in hardware_signatures:
                pos = 0
                while True:
                    pos = mm.find(sig, pos)
                    if pos == -1:
                        break
                    end_pos = mm.find(b'\x00', pos)
                    if end_pos != -1 and end_pos - pos < 200: 
                        device_id = mm[pos:end_pos].decode('ascii', errors='ignore')
                        if len(device_id) > 5: 
                            found_items['hardware'].append(device_id)
                    pos += 1
            
            mm.close()
            
    except Exception as e:
        print(f"[!] Memory analysis encountered an issue: {str(e)}")
    
    found_items['applications'] = list(dict.fromkeys(found_items['applications']))
    found_items['elevated_perms'] = list(dict.fromkeys(found_items['elevated_perms']))
    found_items['hardware'] = list(dict.fromkeys(found_items['hardware']))
    
    found_items['applications'].sort()
    found_items['elevated_perms'].sort()
    found_items['hardware'].sort()
    
    return found_items

def extract_strings_from_memory(dump_file, min_length=4):
    strings = []
    current_string = ''
    
    try:
        with open(dump_file, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                    
                for byte in chunk:
                    try:
                        char = chr(byte)
                        if char.isprintable() and not char.isspace():
                            current_string += char
                        elif len(current_string) >= min_length:
                            if any(keyword in current_string.lower() for keyword in 
                                ['exe', 'dll', 'http', 'https', 'com', 'net', 'org', 
                                 'password', 'user', 'login', 'email', 'admin']):
                                strings.append(current_string)
                            current_string = ''
                        else:
                            current_string = ''
                    except:
                        if len(current_string) >= min_length:
                            strings.append(current_string)
                        current_string = ''
    except Exception as e:
        print(f"String extraction encountered an issue: {str(e)}")
    
    return list(dict.fromkeys(strings))

def write_formatted_report(report_file, processes, strings):
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("=== Memory Analysis Report ===\n\n")
        
        f.write("1. System Processes\n")
        f.write("-" * 50 + "\n")
        system_processes = {k:v for k,v in processes.items() if 'system32' in str(v).lower()}
        for proc, data in system_processes.items():
            f.write(f"Process: {proc}\n")
            f.write(f"Location: {data['offset']}\n")
            f.write("-" * 30 + "\n")
        
        f.write("\n2. User Applications\n")
        f.write("-" * 50 + "\n")
        user_processes = {k:v for k,v in processes.items() if 'system32' not in str(v).lower()}
        for proc, data in user_processes.items():
            f.write(f"Application: {proc}\n")
            f.write(f"Location: {data['offset']}\n")
            f.write("-" * 30 + "\n")
        
        f.write("\n3. Network Activity\n")
        f.write("-" * 50 + "\n")
        network_strings = [s for s in strings if any(x in s.lower() for x in ['http', 'https', 'tcp', 'udp', 'ip'])]
        for net_str in sorted(set(network_strings))[:50]: 
            f.write(f"{net_str}\n")
            
        f.write("\n4. Security Related Items\n")
        f.write("-" * 50 + "\n")
        security_strings = [s for s in strings if any(x in s.lower() for x in 
            ['password', 'key', 'login', 'auth', 'token', 'secret', 'credential'])]
        for sec_str in sorted(set(security_strings))[:50]:  
            f.write(f"{sec_str}\n")
            
        f.write("\n5. File Operations\n")
        f.write("-" * 50 + "\n")
        file_strings = [s for s in strings if any(x in s.lower() for x in ['.exe', '.dll', '.sys', '.bat', '.ps1'])]
        for file_str in sorted(set(file_strings))[:50]: 
            f.write(f"{file_str}\n")

def write_detailed_report(output_file, analysis_results):
    with open(output_file, 'w') as f:
        f.write("=== Detailed Memory Analysis Report ===\n\n")
        
        f.write("1. Applications Found\n")
        f.write("-" * 50 + "\n")
        for app in sorted(set(analysis_results['applications'])):
            f.write(f"- {app}\n")
            
        f.write("\n2. Elevated Permission Usage\n")
        f.write("-" * 50 + "\n")
        for perm in sorted(set(analysis_results['elevated_perms'])):
            f.write(f"- {perm}\n")
            
        f.write("\n3. Hardware Devices Detected\n")
        f.write("-" * 50 + "\n")
        for device in sorted(set(analysis_results['hardware'])):
            f.write(f"- {device}\n")

def main():
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    dump_file = f'memory_dump_{timestamp}.bin'
    report_file = f'ram_analysis_{timestamp}.txt'
    detailed_report = f'detailed_analysis_{timestamp}.txt'
    
    print(f"\n=== Starting RAM Analysis ===")
    print(f"[+] Creating memory dump at: {dump_file}")
    create_memory_dump(dump_file)
    print(f"[+] Memory dump completed successfully")
    
    print(f"\n[+] Starting memory analysis...")
    print(f"[+] Scanning for process signatures")
    processes = scan_memory_for_processes(dump_file)
    print(f"[+] Found {len(processes)} processes in memory")
    
    print(f"\n[+] Analyzing applications and permissions...")
    analysis_results = analyze_applications_and_permissions(dump_file)
    
    print(f"\n[+] Extracting strings from memory...")
    strings = extract_strings_from_memory(dump_file)
    print(f"[+] Extracted {len(strings)} interesting strings")
    
    print(f"\n[+] Generating formatted reports...")
    write_formatted_report(report_file, processes, strings)
    write_detailed_report(detailed_report, analysis_results)
    print(f"[+] Main report generated at: {report_file}")
    print(f"[+] Detailed analysis report generated at: {detailed_report}")
    
    try:
        os.remove(dump_file)
        print(f"\n[+] Cleaned up temporary memory dump file")
    except:
        print(f"\n[!] Note: Memory dump file remains at: {dump_file}")
    
    print(f"\n=== Analysis Complete ===")

if __name__ == "__main__":
    main()
