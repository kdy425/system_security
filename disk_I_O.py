import psutil
import time

def monitor_disk_io(interval=1):
    while True:
        disk_io = psutil.disk_io_counters()
        print(f"디스크 읽기 (bytes): {disk_io.read_bytes}")
        print(f"디스크 쓰기 (bytes): {disk_io.write_bytes}")
        print(f"디스크 읽기 (count): {disk_io.read_count}")
        print(f"디스크 쓰기 (count): {disk_io.write_count}")
        print(f"디스크 읽기 시간 (ms): {disk_io.read_time}")
        print(f"디스크 쓰기 시간 (ms): {disk_io.write_time}")
        print("----")
        time.sleep(interval)

if __name__ == "__main__":
    monitor_disk_io()