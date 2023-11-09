import psutil
import time

def Get_Size(bytes):
    """
    Returns size of bytes in a nice format
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024

def Moitor_Diskio(interval=1):
    while True:
        disk_io = psutil.disk_io_counters()
        print(f"디스크 읽기 (bytes):", Get_Size(disk_io.read_bytes))
        print(f"디스크 쓰기 (bytes):", Get_Size(disk_io.write_bytes))
        print(f"디스크 읽기 (count):", Get_Size(disk_io.read_count))
        print(f"디스크 쓰기 (count):", Get_Size (disk_io.write_count))
        print(f"디스크 읽기 시간 (ms): {disk_io.read_time}")
        print(f"디스크 쓰기 시간 (ms): {disk_io.write_time}")
        print("----")
        time.sleep(interval)

if __name__ == "__main__":
    Moitor_Diskio()