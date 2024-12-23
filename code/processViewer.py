import datetime
import psutil
from tabulate import tabulate
import os
import time
import ctypes

def get_processes():
    procs = []  #각 프로세스의 정보를 저장 리스트
    for p in psutil.process_iter(): #현재 실행 중인 모든 프로세스를 순회
        with p.oneshot():   #각 프로세스에 대한 정보를 한 번에 모두 가져오는 것이 아니라 필요한 정보를 필요할 때마다 개별적으로 가져옴
            pid = p.pid
            if pid == 0:    #프로세스의 PID(프로세스 식별자)
                continue
            name = p.name()  #프로세스 이름
            try:
                create_time = datetime.datetime.fromtimestamp(p.create_time())  #생성된 시간
            except OSError:
                create_time = datetime.datetime.fromtimestamp(psutil.boot_time())
            cpu_usage = p.cpu_percent() #cpu 사용률
            try:
                cpu_affinity = len(p.cpu_affinity())    #프로세스가 사용하는 CPU 코어의 개수
            except psutil.AccessDenied:
                cpu_affinity = 0
            status = p.status() #프로세스의 상태
            try:
                memory = p.memory_full_info().uss   #프로세스가 사용하는 메모리 양
            except psutil.AccessDenied:
                memory = 0
            try:
                user = p.username() #프로세스를 실행하는 사용자
            except psutil.AccessDenied:
                user = "N/A"
            
            # 네트워크 연결 정보를 가져옴
            network_connections = get_network_connections(pid)
            # 열린 포트 정보를 가져옴
            open_ports = get_open_ports(pid)

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
            'network_connection': "Yes" if network_connections else "No",  # 네트워크 사용 여부 추가
            'open_ports': ', '.join(map(str, open_ports))  # 열린 포트 정보를 문자열로 출력
        })
    return procs


#바이트 크기를 가장 적합한 단위로 변환하여 문자열로 반환하는 함수
def get_size(bytes):
    for i in ['', 'K', 'M', 'G', 'T', 'P', 'E']:    #킬로바이트, 메가바이트 ...
        if bytes < 1024:
            return f"{bytes:.2f}{i}B"
        bytes /= 1024

#print 함수   
def print_processes(ps):
    print(tabulate(ps, headers="keys", tablefmt='simple'))

#네트워크 연결 유무
def get_network_connections(pid):
    try:
        connections = psutil.net_connections(kind='all')     #현재 시스템의 모든 네트워크 연결 정보 가져옴
        pid_connections = [conn for conn in connections if conn.pid == pid] #pid 가 매개변수로 전달된 pid 와 일치하는 프로세스 연결 정보만을 걸래냄
        return pid_connections
    except Exception as e:
        print(f"Error fetching network connections: {e}")
        return []
    
#열린포트 번호    
def get_open_ports(pid):
    try:
        connections = psutil.net_connections(kind='inet')    # IPv4 주소 체계에 기반한 연결 정보를 검색하라는 것을 나타냄
        pid_ports = [conn.laddr.port for conn in connections if conn.pid == pid]    #각 연결 정보에서 laddr.port는 로컬 주소의 포트 번호를 나타냄
        return pid_ports
    except Exception as e:
        print(f"Error fetching open ports: {e}")
        return []


#실행
procs = get_processes()
print_processes(procs)

################################################################################
#메모장에 저장하기
#본인 경로에 맞게 수정 해야 함
'''
output = print_processes(get_processes())
output_file_path = "C:\\Users\\ehdbs\\OneDrive\\바탕 화면\\네트워크 대역폭 사용량.txt"  
with open(output_file_path, "w") as output_file:
    output_file.write(output)

print(f"{output_file_path} 저장완료.")
'''


#엑셀로 저장 
#세로줄 안맞음 조정 해야 함
#본인 경로에 맞게 수정 해야 함
'''
output = print_processes(get_processes())
output_file_path = "C:\\Users\\ehdbs\\OneDrive\\바탕 화면\\통합 문서1.csv"
with open(output_file_path, "w") as output_file:
    output_file.write(output)
'''
################################################################################