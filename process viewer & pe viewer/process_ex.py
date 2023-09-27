import datetime
import psutil
from tabulate import tabulate
import os
import time
import ctypes

def get_processes():
    procs = []
    for p in psutil.process_iter():
        with p.oneshot():
            pid = p.pid
            if pid == 0:
                continue
            name = p.name()
            try:
                create_time = datetime.datetime.fromtimestamp(p.create_time())
            except OSError:
                create_time = datetime.datetime.fromtimestamp(psutil.boot_time())
            cpu_usage = p.cpu_percent()
            try:
                cpu_affinity = len(p.cpu_affinity())
            except psutil.AccessDenied:
                cpu_affinity = 0
            status = p.status()
            try:
                memory = p.memory_full_info().uss
            except psutil.AccessDenied:
                memory = 0
            try:
                user = p.username()
            except psutil.AccessDenied:
                user = "N/A"
            
            # 네트워크 연결 정보를 가져옴
            network_connections = get_network_connections(pid)
            # 열린 포트 정보를 가져옴
            open_ports = get_open_ports(pid)

        procs.append({
            'pid': pid,
            'name': name,
            'create_time': create_time,
            'cpu_usage': cpu_usage,
            'cpu_affinity': cpu_affinity,
            'status': status,
            'memory': get_size(memory),
            'user': user,
            'network_usage': "Yes" if network_connections else "No",  # 네트워크 사용 여부 추가
            'open_ports': ', '.join(map(str, open_ports))  # 열린 포트 정보를 문자열로 출력
        })
    return procs

def get_size(bytes):
    for i in ['', 'K', 'M', 'G', 'T', 'P', 'E']:
        if bytes < 1024:
            return f"{bytes:.2f}{i}B"
        bytes /= 1024

def print_processes(ps):
    print(tabulate(ps, headers="keys", tablefmt='simple'))

def get_network_connections(pid):
    try:
        connections = psutil.net_connections(kind='all')
        pid_connections = [conn for conn in connections if conn.pid == pid]
        return pid_connections
    except Exception as e:
        print(f"Error fetching network connections: {e}")
        return []
    
def get_open_ports(pid):
    try:
        connections = psutil.net_connections(kind='inet')
        pid_ports = [conn.laddr.port for conn in connections if conn.pid == pid]
        return pid_ports
    except Exception as e:
        print(f"Error fetching open ports: {e}")
        return []

procs = get_processes()
print_processes(procs)

