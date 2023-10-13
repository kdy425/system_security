import psutil

def get_size(bytes):
    for i in ['', 'K', 'M', 'G', 'T', 'P', 'E']:
        if bytes < 1024:
            return f"{bytes:.2f}{i}B"
        bytes /= 1024

procs = []

for p in psutil.process_iter():
    with p.oneshot():
        pid = p.pid
        try:
            memory_info = p.memory_full_info()
            memory = memory_info.uss
            procs.append({'pid': pid, 'memory': memory})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# 메모리 크기를 기준으로 내림차순으로 정렬
procs.sort(key=lambda x: x['memory'], reverse=True)

# 정렬된 정보를 저장할 배열
sorted_network = []

for proc in procs:
    pid = proc['pid']
    memory = get_size(proc['memory'])
    sorted_network.append({'pid': pid, 'memory': memory})

# 모든 정보가 저장된 배열 출력
for proc in sorted_network:
    print(f"PID: {proc['pid']}, Memory: {proc['memory']}")