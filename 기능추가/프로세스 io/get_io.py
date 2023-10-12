#프로세스 io
import psutil

def get_size(bytes):
    """
    Returns size of bytes in a nice format
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024

def get_io_status(pid):
    try:
        process = psutil.Process(pid)
        io_counters = process.io_counters()
        
        io_status = {
            "read_bytes": get_size(io_counters.read_bytes),
            "write_bytes": get_size(io_counters.write_bytes),
            "read_count": io_counters.read_count,
            "write_count": io_counters.write_count,
        }

        return io_status

    except psutil.NoSuchProcess:
        return "Process with PID {} not found.".format(pid)

# Example usage
pid = 23672  # Replace with the PID of the process you want to monitor
io_status = get_io_status(pid)
print("I/O Status for PID", pid)
for key, value in io_status.items():
    print(f"{key}: {value}")
