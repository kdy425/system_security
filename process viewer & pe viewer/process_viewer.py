import datetime
import psutil
from tabulate import tabulate
import pandas as pd


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
            # 네트워크 사용량 정보를 가져옴
            #network_usage = get_network_usage(pid)


#print할 부분
        procs.append({
            'pid': pid,
            'name': name,
            'create_time': create_time,
            'cpu_usage': cpu_usage,
            'cpu_affinity': cpu_affinity,
            'status': status,
            'memory': get_size(memory),
            'user': user,
            'network_connections': len(network_connections),
            'open_ports': ', '.join(map(str, open_ports)),
            #'network_usage_sent': get_size(network_usage['sent_bytes']),
            #'network_usage_received': get_size(network_usage['received_bytes'])
        })
    return procs



#바이트 크기를 가장 적합한 단위로 변환하여 문자열로 반환하는 함수
def get_size(bytes):
    for i in ['', 'K', 'M', 'G', 'T', 'P', 'E']:
        if bytes < 1024:
            return f"{bytes:.2f}{i}B"
        bytes /= 1024
        
        
#print 함수        
def print_processes(ps):
    table = tabulate(ps, headers="keys", tablefmt='simple')
    return table if table else ""


#네트워크 연결 유무
def get_network_connections(pid):  
    try:
        connections = psutil.net_connections(kind='all')
        pid_connections = [conn for conn in connections if conn.pid == pid]
        return pid_connections
    except Exception as e:
        print(f"Error fetching network connections: {e}")
        return []
    

#열린포트 번호
def get_open_ports(pid):  
    try:
        connections = psutil.net_connections(kind='inet')
        pid_ports = [conn.laddr.port for conn in connections if conn.pid == pid]
        return pid_ports
    except Exception as e:
        print(f"Error fetching open ports: {e}")
        return []
    
######################################################################################################


#####################################################################################################
#오류 있음
#각 프로세스 마다 사용량이 안나오는 문제가 있음
'''def get_network_usage(pid): #네트워크 사용량
    try:
        io = psutil.net_io_counters()
        bytes_sent, bytes_recv = io.bytes_sent, io.bytes_recv
        io_2 = psutil.net_io_counters()
        sent_bytes, recv_bytes = io_2.bytes_sent - bytes_sent, io_2.bytes_recv - bytes_recv
        return {
            'sent_bytes': sent_bytes,
            'received_bytes': recv_bytes
        }
    except Exception as e:
        print(f"Error fetching network usage: {e}")
        return {'sent_bytes': 0, 'received_bytes': 0}'''
    


#########################################################################################################


#메모장에 실행 결과 저장
'''
output = print_processes(get_processes())
output_file_path = "C:\\Users\\ehdbs\\OneDrive\\바탕 화면\\네트워크 대역폭 사용량.txt"
with open(output_file_path, "w") as output_file:
    output_file.write(output)

print(f"프로그램 실행 결과가 {output_file_path} 파일에 저장되었습니다.")'''



#엑셀로 저장 
#세로줄 안맞음 조정 해야 함
'''
output = print_processes(get_processes())
output_file_path = "C:\\Users\\ehdbs\\OneDrive\\바탕 화면\\통합 문서1.csv"
with open(output_file_path, "w") as output_file:
    output_file.write(output)
'''



#그냥 실행

procs = get_processes()
print_processes(procs)
