import tkinter as tk
from tkinter import ttk
import subprocess
import pefile
import datetime
import logging
import psutil
from tabulate import tabulate
import os
import time
import ctypes
import matplotlib.pyplot as plt
from collections import deque
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import sys
from tkinter import scrolledtext, Scrollbar
from tkinter import Menu  # 컨텍스트 메뉴 생성을 위해 추가
from scapy.all import sniff
import threading
####################################################################################
#외부 함수 import
from load_dll import load_dll
from peviewer import get_pe_info
from location import get_process_location
from terminate import terminate_process
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
#print_processes(procs)


#########################################################################################################################################
def end_process(self):
    value = self.get_pid()
    pid = int(value)
    try:
        result = terminate_process(pid)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e.returncode} - {e.output}"


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
        self.root.title("process viewer")
         # 열 별로 정렬 방향을 저장할 변수
        self.sort_direction = {}
        #######################추가코드###############################
        self.create_widgets()
        self.current_procs = []  # 현재 모니터링 중인 프로세스 PID
        self.timer_ids = []  # 타이머 식별자
        self.previous_memory_usage = {}  # 이전 메모리 사용량
        self.new_pids = []  # 입력받은 새로운 프로세스 PID
        ##############################################################

        # 프로세스 정보를 저장할 표(Table) 생성
        self.tree = ttk.Treeview(root, columns=list(procs[0].keys()), show="headings")
        for key in procs[0].keys():
            # 정렬 방향 변수 초기화
            self.sort_direction[key] = True
            
            # 열 제목을 클릭할 때 정렬 함수 호출
            self.tree.heading(key, text=key, command=lambda col=key: self.sort_table(col))
            self.tree.column(key, width=100)
        
        # 표에 프로세스 정보 삽입
        self.update_process_list()


        #버튼 프레임 생성
        button_frame = ttk.Frame(root)
        button_frame.pack(side="top", fill="x")

        # "Refresh" button
        self.refresh_button = ttk.Button(button_frame, text="refresh", command=self.update_process_list)
        self.refresh_button.pack(side="left", padx=0)

        # "end process" button
        self.run_peviewer_button = ttk.Button(button_frame, text="end process", command=self.run_end_process)
        self.run_peviewer_button.pack(side="left", padx=0)

        # "Packet Capture" button
        self.packet_button = ttk.Button(button_frame, text="packet capture", command=self.run_packet_capture)
        self.packet_button.pack(side="left", padx=0)

        ###추가사항-disk/io#####
        self.disk_button = ttk.Button(button_frame, text="Disk", command=self.run_disk_monitoring)
        self.disk_button.pack(side="left", padx=0)
        #######

        # 표 스크롤바 추가
        self.scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        
        # 표와 스크롤바 배치
        self.tree.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")


        # 표의 이벤트 리스너 등록
        self.tree.bind("<ButtonRelease-1>", self.on_item_click)#좌클릭 이벤트(release)
        self.tree.bind("<Button-3>", self.show_context_menu)  # 우클릭 이벤트 리스너 등록

        # 컨텍스트 메뉴 생성
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="PEViewer", command=self.run_peviewer_and_display_result)
        self.context_menu.add_command(label="dll", command=self.run_load_dll_and_display_result)
        self.context_menu.add_command(label="location", command=self.run_get_process_location_and_display_result)
        self.context_menu.add_command(label="Graphy", command=self.graphy)

        
###########################추가코드###########################
    def create_widgets(self):
        self.pid_entry = ttk.Entry(self.root)
        self.pid_entry.pack(side="bottom", pady=10)
        ttk.Button(self.root, text="Start Monitoring", command=self.start_monitoring).pack(pady=10)
        ttk.Button(self.root, text="Stop Monitoring", command=self.stop_monitoring_button_click).pack(pady=10)
        self.log_text = tk.Text(self.root, height=30, width=60)
        self.log_text.pack(side="bottom", pady=10)



    def run_disk_monitoring(self):
        def disk_monitoring():
            while True:
                disk_io = psutil.disk_io_counters()
                result = (
                    f"Read Disk (bytes): {disk_io.read_bytes}\n"
                    f"Write disk (bytes): {disk_io.write_bytes}\n"
                    f"Read Disk (count): {disk_io.read_count}\n"
                    f"Write disk (count): {disk_io.write_count}\n"
                    f"Disk Read Time (ms): {disk_io.read_time}\n"
                    f"Disk Write Time (ms): {disk_io.write_time}\n"
                    "----\n"
                )
                self.log_text.insert(tk.END, result)
                self.log_text.yview(tk.END)
                time.sleep(1)

        # Create a new thread for disk monitoring
        threading.Thread(target=disk_monitoring, daemon=True).start()

    
###############################################################

    def run_packet_capture(self):
    # 패킷 캡처 함수
        def packet_capture(interface):
            sniff(iface=interface, prn=lambda x: pkt_listbox.insert(tk.END, str(x)))

        # GUI 생성
        app = tk.Tk()
        app.title("프로세스 뷰어 및 패킷 캡처")

        # Set the window size
        app.geometry("700x400")  # 창 크기 조절

        # 패킷 캡처
        pkt_frame = ttk.Frame(app)
        pkt_frame.pack(fill="both", expand=True)  # 창 채우기

        interface_entry = ttk.Entry(pkt_frame)
        interface_entry.grid(row=0, column=1)

        start_button = ttk.Button(pkt_frame, text="패킷 캡처 시작", command=lambda: threading.Thread(target=packet_capture, args=(interface_entry.get(),)).start())
        start_button.grid(row=0, column=2)

        # 패킷 캡처 결과에 스크롤바 추가
        pkt_listbox = tk.Listbox(pkt_frame)
        pkt_listbox.grid(row=1, column=0, columnspan=3, sticky="nsew")  # Make the listbox expand
        


        pkt_frame.columnconfigure(0, weight=1)
        pkt_frame.rowconfigure(1, weight=1)

        # 스크롤바 추가
        scrollbar = Scrollbar(pkt_frame, orient=tk.VERTICAL)
        scrollbar.config(command=pkt_listbox.yview)
        scrollbar.grid(row=1, column=3, sticky="ns")

        pkt_listbox.config(yscrollcommand=scrollbar.set)

        app.mainloop()



####################################################################################################################################################
    # 메모리 크기를 숫자 값으로 변환하기 위한 함수
    def convert_memory(self, memory_str):
        try:
            size = float(memory_str[:-2])
            unit = memory_str[-2:].upper()
            units = {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4, 'PB': 1024**5, 'EB': 1024**6}
            return size * units.get(unit, 1)  # 기본값 1로 설정
        except ValueError:
            return 0  # 오류 발생 시 0으로 처리



     # 정렬 함수
    def sort_table(self, column):
        # 현재 정렬 방향 확인
        direction = self.sort_direction[column]

        # 정렬 방향에 따라 정렬 수행
        if column == 'memory':
            # 메모리 크기를 정렬하기 위한 수치 값으로 변환
            procs.sort(key=lambda x: self.convert_memory(x[column]), reverse=not direction)
        else:
            procs.sort(key=lambda x: x[column], reverse=not direction)

        # 정렬 방향 변경
        self.sort_direction[column] = not direction

        # 기존 표 내용을 삭제
        for item in self.tree.get_children():
            self.tree.delete(item)

        # 정렬된 데이터로 표 채우기
        for i, proc in enumerate(procs):
            self.tree.insert("", "end", values=list(proc.values()))
##################################################################################################################################################


    # 프로세스 목록을 업데이트하는 함수
    def update_process_list(self):
        global procs  # 전역 변수로 procs를 사용합니다.
        procs = get_processes()
        # 표를 초기화하고 새로운 프로세스 정보를 삽입
        for item in self.tree.get_children():
            self.tree.delete(item)
        for i, proc in enumerate(procs):
            self.tree.insert("", "end", values=list(proc.values()))

####################################추가코드###################################################
    def start_monitoring(self):
        try:
            self.new_pids = [int(pid.strip()) for pid in self.pid_entry.get().split(',')]
            configure_logging()

            # 현재 모니터링 중인 프로세스가 있다면 중지
            if self.current_procs:
                self.stop_monitoring()

            # 구분선
            separator_line = "\n----------------------------------------\n"
            self.log_text.insert(tk.END, separator_line)
            self.log_text.yview(tk.END)

            # 사용량 출력 시작
            self.print_one_second_usage()

        except ValueError:
            logging.error("Invalid PID(s). Please enter valid integer PIDs separated by commas.")


    
    def print_one_second_usage(self):
        # 1초 사용량 출력
        for pid in self.new_pids:
            self.monitor_process(pid)

        separator_line = "\n----------------------------------------\n"
        self.log_text.insert(tk.END, separator_line)
        self.log_text.yview(tk.END)

        # 다음 1초 동안 정보 불러오기
        if self.current_procs:  # 현재 모니터링 중인 프로세스가 있다면 계속 출력
            self.timer_ids.append(self.root.after(1000, self.print_one_second_usage))

    def monitor_process(self, pid):
        try:
            # PID에 대한 CPU 및 메모리 사용량 불러오기
            process = psutil.Process(pid)
            cpu_percent = round(process.cpu_percent(interval=0.05), 2)
            current_memory_usage = round(process.memory_info().rss / (1024 ** 2), 2)

            if pid in self.previous_memory_usage:
                memory_change = round(current_memory_usage - self.previous_memory_usage[pid], 2)
            else:
                memory_change = 0.0

            # 사용량 정보
            log_message = (
                f"\n-------- Process Resource Usage Log --------\n"
                f"Process PID: {pid}\n"
                f"CPU usage: {cpu_percent}%\n"
                f"Memory usage: {current_memory_usage} MB\n"
                f"Memory change amount: {memory_change} MB\n"
            )

            self.log_text.insert(tk.END, log_message)
            self.log_text.yview(tk.END)

            self.previous_memory_usage[pid] = current_memory_usage

        except psutil.NoSuchProcess as e:
            logging.error(f"Process not found with PID {pid}: {e}")
        except Exception as e:
            logging.error(f"An error has occurred: {e}")

    def stop_monitoring_button_click(self):
        self.stop_monitoring()

    def stop_monitoring(self):
        # 현재 실행 중인 타이머 중지 후 상태 초기화
        for timer_id in self.timer_ids:
            self.root.after_cancel(timer_id)

        self.current_procs = []
        self.timer_ids = []
        self.previous_memory_usage = {}

        # 마지막 구분선 이후의 출력 삭제
        idx = self.log_text.search("\n----------------------------------------\n", tk.END)
        if idx:
            self.log_text.delete(idx, tk.END)

        # "-------- Process Resource Usage Log --------" 라인을 추가하여 더 이상의 로그가 출력되지 않도록 함
        self.log_text.insert(tk.END, "-------- Process Resource Usage Log --------\n")



    def update_cpu_graph(self):
        max_data_points = 50
        cpu_usage_data = deque(maxlen=max_data_points)
        time_data = deque(maxlen=max_data_points)

        plt.ion()
        fig, ax1 = plt.subplots()

        ax1.set_xlabel('Time')
        ax1.set_ylabel('CPU utilization (%)', color='tab:blue')

        def inner_update():
            try:
                process = psutil.Process(self)
                cpu_percent = process.cpu_percent(interval=1)

                cpu_usage_data.append(cpu_percent)
                time_data.append(time.strftime('%H:%M:%S'))

                ax1.clear()
                ax1.set_xlabel('Time')
                ax1.set_ylabel('CPU utilization (%)', color='tab:blue')
                ax1.plot(time_data, cpu_usage_data, color='tab:blue', label='CPU 사용률')

            # y 축 범위를 자동으로 조정
                ax1.relim()
                ax1.autoscale_view()

                fig.tight_layout()
                plt.xticks(rotation=45)
                plt.draw()
                plt.pause(0.01)
            except psutil.NoSuchProcess:
                print(f"Unable to find process corresponding to PID {self}")
                plt.ioff()

        return inner_update
#################################################################################################


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
    

    def run_end_process(self):
        result = end_process(self)
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("location Result")
        
        # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)

##########################################################################################
    def graphy(self):
        # ProcessViewerApp 클래스의 객체 생성
        process_viewer_app = ProcessViewerApp(self.root)
    
    # 객체의 메서드 호출
        result = process_viewer_app.update_cpu_graph()
    
    # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("location Result")
    
    # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)
###################################################################################


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

##########################추가코드#############################################################
def configure_logging():
    # 로깅 정보 초기화
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
###############################################################################################


def main():
    root = tk.Tk()
    app = ProcessViewerApp(root)
    #root.geometry("1500x600")  # 원하는 크기로 수정
    root.mainloop()

if __name__ == "__main__":
    main()

#############################################################################################