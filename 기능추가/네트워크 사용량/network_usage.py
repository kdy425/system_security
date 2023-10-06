#실시간 네트워크 사용량

import psutil
import time

UPDATE_DELAY = 1  # in seconds

def get_size(bytes):
    """
    Returns size of bytes in a nice format
    """
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f"{bytes:.2f}{unit}B"
        bytes /= 1024

def network_usage():
    bytes_sent, bytes_recv = psutil.net_io_counters().bytes_sent, psutil.net_io_counters().bytes_recv

    while True:
        time.sleep(UPDATE_DELAY)
        io = psutil.net_io_counters()
        us, ds = io.bytes_sent - bytes_sent, io.bytes_recv - bytes_recv
        print(#f"Upload: {get_size(io_2.bytes_sent)}   "
              #f"Download: {get_size(io_2.bytes_recv)}   "
              f"Upload Speed: {get_size(us / UPDATE_DELAY)}/s   "
              f"Download Speed: {get_size(ds / UPDATE_DELAY)}/s      ", end="\r")
        bytes_sent, bytes_recv = io.bytes_sent, io.bytes_recv

if __name__ == "__main__":
    network_usage()
