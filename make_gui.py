import tkinter as tk
from tkinter import ttk, scrolledtext, Entry, Label, Button, filedialog, messagebox, Menu,Scrollbar
import subprocess
import pefile
import datetime
import psutil
from tabulate import tabulate
import os
import time
import ctypes
import sys
from scapy.all import sniff
import threading
import urllib.parse
import urllib.request
import json

####################################################################################
#외부 함수 import
from load_dll import load_dll
#from peviewer import get_pe_info
from location import get_process_location
from terminate import terminate_process
from network_info import get_network_info
from process_info import get_process_info
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


'''def run_peviewer(self):
    value = self.get_pid()
    pid = int(value)
    try:
        result = get_pe_info(pid)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e.returncode} - {e.output}"'''
    
def run_get_network_info(self):
    value = self.get_pid()
    pid = int(value)
    try:
        result = get_network_info(pid)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e.returncode} - {e.output}"
    
def run_get_process_info(self):
    value = self.get_pid()
    pid = int(value)
    try:
        result = get_process_info(pid)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e.returncode} - {e.output}"
            


class ProcessViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("프로세스 뷰어")
         # 열 별로 정렬 방향을 저장할 변수
        self.sort_direction = {}
        
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


        # "VT" button
        self.packet_button = ttk.Button(button_frame, text="VirusTotal", command=self.run_vt_scan)
        self.packet_button.pack(side="left", padx=0)
        

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
        #self.context_menu.add_command(label="PEViewer", command=self.run_peviewer_and_display_result)
        self.context_menu.add_command(label="dll", command=self.run_load_dll_and_display_result)
        self.context_menu.add_command(label="location", command=self.run_get_process_location_and_display_result)
        self.context_menu.add_command(label="network info", command=self.run_get_process_network_info_result)
        self.context_menu.add_command(label="process info", command=self.run_get_process_info_result)

    def run_vt_scan(self):
        # VirusTotal 스캔 실행 함수
        vt_result_window = tk.Toplevel(self.root)
        vt_result_app = get_VT_result(vt_result_window)

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

    def run_get_process_network_info_result(self):
        result = run_get_network_info(self)
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("location Result")
        
        # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)


    def run_get_process_info_result(self):
        result = run_get_process_info(self)
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("location Result")
        
        # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)



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


    '''def run_peviewer_and_display_result(self):
        result = run_peviewer(self)
        
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("PEViewer Result")
        
       # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)'''
    

    # 컨텍스트 메뉴 표시
    def show_context_menu(self, event):
        self.context_menu.post(event.x_root, event.y_root)



#바이러스 토탈 실행행
class get_VT_result:
    def __init__(self, root):
        self.root = root
        self.root.title("VirusTotal 결과")
        self.stop_flag = False  # 검사 중지 플래그 추가
        self.create_widgets()
        self.completed_tests = 0  # 완료한 검사 횟수
        self.wait_time = 60  # 초기 대기 시간 설정 (초)

    def create_widgets(self):
        # API 키를 입력 받을 Entry 위젯 추가
        self.api_key_label = Label(self.root, text="VIRUS TOTAL 접속 API키")
        self.api_key_label.pack()

        self.api_key_entry = Entry(self.root, width=40)
        self.api_key_entry.pack(pady=5)

        # 파일을 선택할 버튼과 선택된 파일 경로를 표시할 레이블 추가
        self.file_path_label = Label(self.root, text="대조할 정보 파일 선택")
        self.file_path_label.pack(pady=5)

        self.select_file_button = Button(self.root, text="파일 선택", command=self.browse_file)
        self.select_file_button.pack(pady=5)

        # 파일 선택 설명 레이블 추가
        self.file_desc_label = Label(self.root, text="이 검사는 VirusTotal의 데이터베이스를 이용합니다.\n"
                                                     "무료 계정의 경우 1분에 1번의 검사를 실행할 수 있으며, 1번 검사에 4개의 값을 검사합니다.")
        self.file_desc_label.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20)
        self.result_text.pack(padx=10, pady=10)

        # 검사 실행 및 중지 버튼 추가
        self.run_button = tk.Button(self.root, text="실행", command=self.start_vt_thread)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.root, text="검사 종료", command=self.stop_vt)
        self.stop_button.pack(side=tk.RIGHT, padx=5)

        self.stop_label = tk.Label(self.root, text="", fg="red", anchor="w")
        self.stop_label.pack(side=tk.RIGHT, padx=5, fill="both")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_label.config(text=f"선택된 파일: {file_path}")

    def get_virus_total(self, api_key, file_path):
        HOST = 'www.virustotal.com'
        SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
        REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

        fields = [('apikey', api_key)]

        with open(file_path, 'r') as txtf:
            count = 0
            while True:
                line = txtf.readline().strip('\n')
                if not line:
                    break
                
                if self.stop_flag:  # 검사 중지 플래그 확인
                    self.stop_flag = False  # 플래그 초기화
                    self.stop_label.config(text="검사가 종료되었습니다.", fg="red")
                    return  # 검사가 중지되면 함수를 종료하여 결과 창이 닫히지 않도록 함

                parameters = {'resource': line, 'apikey': api_key}
                data = urllib.parse.urlencode(parameters).encode('utf-8')
                req = urllib.request.Request(REPORT_URL, data)
                response = urllib.request.urlopen(req)
                data = response.read()
                data = json.loads(data)

                md5 = data.get('md5', {})
                scan = data.get('scans', {})
                keys = scan.keys()

                result = "\n"
                result += "========================================================================="
                if not md5:
                    result += "\n !!!!!!!!! 다음 백신 엔진에 검색한 결과, 일치하는 항목이 없습니다. !!!!!!!!! "
                else:
                    result += '\n해시 : ' + str(md5)
                result += "\n=========================================================================="
                for key in keys:
                    if key in ['AhnLab-V3', 'ALYac', 'ViRobot']:
                        result += '\n%-20s : %s' % (key, scan[key]['result'])

                result += "\n++++++++++++++++" + str(md5) + " 검사 완료 +++++++++++++++++"

                # GUI 업데이트
                self.result_text.insert(tk.END, result)
                self.result_text.update()
                count += 1

                if count == 4:  # 4개의 파일 검사를 마치면 1분 대기 후 count 초기화
                    self.completed_tests += 1
                    remaining_time = self.wait_time
                    while remaining_time > 0:
                        self.stop_label.config(text=f"{self.completed_tests}번째 검사를 완료했습니다. "
                                                    f"다음 무료 검사를 위해 1분 대기 중입니다. "
                                                    f"(남은 시간: {remaining_time}초)", fg="gray")
                        time.sleep(1)
                        remaining_time -= 1
                    count = 0

        # 검사가 완료되면 라벨 업데이트
        self.stop_label.config(text="검사가 완료되었습니다.", fg="green")

    def start_vt_thread(self):
        # 버튼 클릭시 실행되는 함수를 스레드로 실행
        self.stop_label.config(text="검사가 실행 중입니다.", fg="blue")
        self.stop_flag = False  # 검사 중지 플래그 초기화
        api_key = self.api_key_entry.get()
        file_path = self.file_path_label.cget("text").replace("선택된 파일: ", "")

        # 실행 전 결과 텍스트 초기화
        self.result_text.delete(1.0, tk.END)

        # 스레드 시작
        vt_thread = threading.Thread(target=self.get_virus_total, args=(api_key, file_path))
        vt_thread.start()

    def stop_vt(self):
        # 검사 중지 버튼 클릭 시 호출되는 함수
        self.stop_flag = True
        self.stop_label.config(text="검사가 중지되었습니다. 대기시간 계산과 관계없이 바로 창을 닫아도 무방합니다.", fg="orange")

    #if __name__ == "__main__":
        #root = tk.Tk()
        #app = get_VT_result(root)
        #root.mainloop()



   


def main():
    root = tk.Tk()
    app = ProcessViewerApp(root)
    #root.geometry("1500x600")  # 원하는 크기로 수정
    root.mainloop()

if __name__ == "__main__":
    main()

#############################################################################################