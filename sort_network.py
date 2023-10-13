import psutil

def get_network_connections(pid):
    try:
        connections = psutil.net_connections(kind='all')
        pid_connections = [conn for conn in connections if conn.pid == pid]
        return pid_connections
    except Exception as e:
        print(f"Error fetching network connections: {e}")
        return []

procs = []

for p in psutil.process_iter():
    with p.oneshot():
        pid = p.pid
        network_connections = get_network_connections(pid)
        procs.append({'pid': pid, 'network_connections': len(network_connections)})

# 네트워크 연결 수를 기준으로 내림차순으로 정렬
procs.sort(key=lambda x: x['network_connections'], reverse=True)

# 정렬된 정보를 저장할 배열
sorted_procs = []

for proc in procs:
    pid = proc['pid']
    network_connections = proc['network_connections']
    sorted_procs.append({'pid': pid, 'network_connections': network_connections})

# 모든 정보가 저장된 배열 출력
for proc in sorted_procs:
    print(f"PID: {proc['pid']}, Network Connections: {proc['network_connections']}")
