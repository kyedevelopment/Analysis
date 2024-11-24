import os
import datetime
import subprocess
import platform
import winreg
from pathlib import Path

def get_running_processes():
    processes = []
    if platform.system() == "Windows":
        cmd = subprocess.Popen('tasklist /v /fo csv', shell=True, stdout=subprocess.PIPE)
        for line in cmd.stdout.readlines()[1:]:
            try:
                decoded_line = line.decode('utf-8').strip().split(',')
                process_info = {
                    'name': decoded_line[0].strip('"'),
                    'pid': decoded_line[1].strip('"'),
                    'memory': decoded_line[4].strip('"'),
                    'user': decoded_line[6].strip('"')
                }
                processes.append(process_info)
            except:
                continue
    return processes

def get_recent_files(max_days_back=30):
    recent_files = []
    user_profile = os.environ.get('USERPROFILE')
    recent_path = os.path.join(user_profile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent')
    
    current_time = datetime.datetime.now()
    cutoff_date = current_time - datetime.timedelta(days=max_days_back)
    
    if os.path.exists(recent_path):
        for file in os.scandir(recent_path):
            if file.is_file() and file.name.endswith('.lnk'):
                stats = file.stat()
                last_access_time = datetime.datetime.fromtimestamp(stats.st_atime)
                
                if last_access_time > cutoff_date:
                    recent_files.append({
                        'name': file.name[:-4],
                        'last_access': last_access_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'created': datetime.datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    })
    recent_files.sort(key=lambda x: x['last_access'], reverse=True)
    return recent_files

def get_prefetch_data():
    prefetch_files = []
    prefetch_path = "C:\\Windows\\Prefetch"
    
    try:
        if os.path.exists(prefetch_path):
            for file in os.scandir(prefetch_path):
                if file.is_file() and file.name.endswith('.pf'):
                    stats = file.stat()
                    prefetch_files.append({
                        'name': file.name.split('-')[0],
                        'last_access': datetime.datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
                        'created': datetime.datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                    })
    except PermissionError:
        print("Note: Prefetch data requires administrative privileges. Run the script as administrator for full access.")
        return []
    except Exception as e:
        print(f"Error accessing prefetch data: {str(e)}")
        return []
        
    prefetch_files.sort(key=lambda x: x['last_access'], reverse=True)
    return prefetch_files

def main():
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f'forensics_report_{timestamp}.txt'
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=== Digital Forensics Report ===\n\n")
        
        f.write("1. Currently Running Processes\n")
        f.write("-" * 50 + "\n")
        processes = get_running_processes()
        for proc in processes:
            f.write(f"Name: {proc['name']}\n")
            f.write(f"PID: {proc['pid']}\n")
            f.write(f"Memory: {proc['memory']}\n")
            f.write(f"User: {proc['user']}\n")
            f.write("-" * 30 + "\n")
        
        f.write("\n2. Recently Accessed Files (Last 30 Days)\n")
        f.write("-" * 50 + "\n")
        recent_files = get_recent_files(max_days_back=30)
        for file in recent_files:
            f.write(f"Name: {file['name']}\n")
            f.write(f"Last Access: {file['last_access']}\n")
            f.write(f"Created: {file['created']}\n")
            f.write("-" * 30 + "\n")
        
        f.write("\n3. Prefetch Data (Application Execution History)\n")
        f.write("-" * 50 + "\n")
        prefetch_data = get_prefetch_data()
        for pf in prefetch_data:
            f.write(f"Application: {pf['name']}\n")
            f.write(f"Last Execute: {pf['last_access']}\n")
            f.write(f"First Execute: {pf['created']}\n")
            f.write("-" * 30 + "\n")

if __name__ == "__main__":
    main()
