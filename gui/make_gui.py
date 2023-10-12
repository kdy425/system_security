import tkinter as tk
from tkinter import ttk
import subprocess
import pefile
import datetime
import psutil
from tabulate import tabulate
import os
import time
import ctypes
import sys
from tkinter import scrolledtext
####################################################################################
#외부 함수 import
from load_dll import load_dll
from peviewer import get_pe_info
from location import get_process_location
####################################################################################
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
            'network_usage': "Yes" if network_connections else "No",  # 네트워크 사용 여부 추가
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


#########################################################################################################################################
def run_get_process_location(self):
    value = self.get_pid()
    pid = int(value)
    try:
        result = get_process_location(pid)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e.returncode} - {e.output}"


def run_load_dll(self):
    value = self.get_pid()
    pid = int(value)
    try:
        result = load_dll(pid)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e.returncode} - {e.output}"


def run_peviewer(self):
    value = self.get_pid()
    pid = int(value)
    try:
        result = get_pe_info(pid)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e.returncode} - {e.output}"
            


class ProcessViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("프로세스 뷰어")
        
        # 프로세스 정보를 저장할 표(Table) 생성
        self.tree = ttk.Treeview(root, columns=list(procs[0].keys()), show="headings")
        for key in procs[0].keys():
            self.tree.heading(key, text=key)
            self.tree.column(key, width=100)
        
        # 표에 프로세스 정보 삽입
        self.update_process_list()
        
        # 표 스크롤바 추가
        self.scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        
        # 표와 스크롤바 배치
        self.tree.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # "Run PEViewer" 버튼 생성
        self.run_peviewer_button = ttk.Button(root, text="PEViewer", command=self.run_peviewer_and_display_result)
        self.run_peviewer_button.pack(pady=10)

        # "dll" 버튼 생성
        self.run_peviewer_button = ttk.Button(root, text="dll", command=self.run_load_dll_and_display_result)
        self.run_peviewer_button.pack(pady=10)

        # "location" 버튼 생성
        self.run_peviewer_button = ttk.Button(root, text="location", command=self.run_get_process_location_and_display_result)
        self.run_peviewer_button.pack(pady=10)

        # "Refresh" 버튼 생성
        self.refresh_button = ttk.Button(root, text="Refresh", command=self.update_process_list)
        self.refresh_button.pack(pady=10)

        # 표의 이벤트 리스너 등록
        self.tree.bind("<ButtonRelease-1>", self.on_item_click)
        self.tree.bind("<Button-3>", self.show_context_menu)  # 우클릭 이벤트 리스너 등록



    # 프로세스 목록을 업데이트하는 함수
    def update_process_list(self):
        global procs  # 전역 변수로 procs를 사용합니다.
        procs = get_processes()
        # 표를 초기화하고 새로운 프로세스 정보를 삽입
        for item in self.tree.get_children():
            self.tree.delete(item)
        for i, proc in enumerate(procs):
            self.tree.insert("", "end", values=list(proc.values()))

   # 표의 행을 클릭할 때 호출되는 함수
    def on_item_click(self, event):
        item = self.tree.selection()[0]  # 선택한 행의 ID 가져오기
        values = self.tree.item(item, "values")  # 선택한 행의 값(프로세스 정보) 가져오기
        pid_value = values[0]  # PID는 첫 번째 열에 위치한다고 가정
        #print("Selected PID:", pid_value)
        return pid_value



    def get_pid(self):  #프로세스 pid 값 받아오는 함수 int 형으로 형 변환 후에 사용해야 함
        event = None
        pid = self.on_item_click(event)
        result = int(pid)
        return result
    

    def run_get_process_location_and_display_result(self):
        result = run_get_process_location(self)
        
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("location Result")
        
        # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)


    def run_load_dll_and_display_result(self):
        result = run_load_dll(self)
        
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("dll Result")
        
        # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)


    def run_peviewer_and_display_result(self):
        result = run_peviewer(self)
        
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("PEViewer Result")
        
       # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)
    

    # 컨텍스트 메뉴 표시
    def show_context_menu(self, event):
        self.context_menu.post(event.x_root, event.y_root)


def main():
    root = tk.Tk()
    app = ProcessViewerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

#############################################################################################