#프로세스 io
import psutil

def Get_Size(bytes):
    """
    Returns size of bytes in a nice format
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024

def Get_Io_Status(pid):
    try:
        process = psutil.Process(pid)
        io_counters = process.io_counters()
        
        io_status = {
            "read_bytes": Get_Size(io_counters.read_bytes),
            "write_bytes": Get_Size(io_counters.write_bytes),
            "read_count": io_counters.read_count,
            "write_count": io_counters.write_count,
        }

        return io_status

    except psutil.NoSuchProcess:
        return "Process with PID {} not found.".format(pid)

# Example usage
pid = 10420  # Replace with the PID of the process you want to monitor
io_status = Get_Io_Status(pid)
print("I/O Status for PID", pid)
for key, value in io_status.items():
    print(f"{key}: {value}")
