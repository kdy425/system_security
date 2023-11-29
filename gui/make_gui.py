import tkinter as tk
from tkinter import ttk, scrolledtext, Entry, Label, Button, filedialog, messagebox, Menu, Scrollbar, \
    simpledialog  # simpledialog추가_11.29
import subprocess
import pefile
import datetime
import psutil
from setuptools import logging
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
import hashlib
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import re
import win32evtlog
import logging
# from up import is_admin

####################################################################################
# 외부 함수 import
from GUIevent import create_gui, on_read_log_button_click, run_as_admin, read_security_event_log, result_text
from GUIuse import ProcessMonitorApp
from GUIuses import stop_monitoring, print_one_second_usage, configure_logging, start_monitoring, toggle_monitoring
from load_dll import load_dll
from peviewer import get_pe_info
from location import get_process_location
from terminate import terminate_process
from network_info import get_network_info
from process_info import get_process_info

VT_KEY = '1462641f17f8d8412cfd1aa7b00be2d4e30ff73068549ab76463464230a9b74c'


####################################################################################
def get_processes():
    procs = []  # 각 프로세스의 정보를 저장 리스트
    for p in psutil.process_iter():  # 현재 실행 중인 모든 프로세스를 순회
        with p.oneshot():  # 각 프로세스에 대한 정보를 한 번에 모두 가져오는 것이 아니라 필요한 정보를 필요할 때마다 개별적으로 가져옴
            pid = p.pid
            if pid == 0:  # 프로세스의 PID(프로세스 식별자)
                continue
            name = p.name()  # 프로세스 이름
            try:
                create_time = datetime.datetime.fromtimestamp(p.create_time())  # 생성된 시간
            except OSError:
                create_time = datetime.datetime.fromtimestamp(psutil.boot_time())
            cpu_usage = p.cpu_percent()  # cpu 사용률
            try:
                cpu_affinity = len(p.cpu_affinity())  # 프로세스가 사용하는 CPU 코어의 개수
            except psutil.AccessDenied:
                cpu_affinity = 0
            status = p.status()  # 프로세스의 상태
            try:
                memory = p.memory_full_info().uss  # 프로세스가 사용하는 메모리 양
            except psutil.AccessDenied:
                memory = 0
            try:
                user = p.username()  # 프로세스를 실행하는 사용자
            except psutil.AccessDenied:
                user = "N/A"

            # 네트워크 연결 정보를 가져옴
            network_connections = get_network_connections(pid)

        # print할 부분
        procs.append({
            'pid': pid,
            'name': name,
            'create_time': create_time,
            'cpu_usage': cpu_usage,
            'cpu_affinity': cpu_affinity,
            'status': status,
            'memory': get_size(memory),
            'user': user,
            'memory_bytes': memory,  # ME_11.24_검색기능필요
            'network_usage': "Yes" if network_connections else "No",  # 네트워크 사용 여부 추가
        })
    return procs


# 바이트 크기를 가장 적합한 단위로 변환하여 문자열로 반환하는 함수
def get_size(bytes):
    for i in ['', 'K', 'M', 'G', 'T', 'P', 'E']:  # 킬로바이트, 메가바이트 ...
        if bytes < 1024:
            return f"{bytes:.2f}{i}B"
        bytes /= 1024


# print 함수
def print_processes(ps):
    print(tabulate(ps, headers="keys", tablefmt='simple'))


# 네트워크 연결 유무
def get_network_connections(pid):
    try:
        connections = psutil.net_connections(kind='all')  # 현재 시스템의 모든 네트워크 연결 정보 가져옴
        pid_connections = [conn for conn in connections if
                           conn.pid == pid]  # pid 가 매개변수로 전달된 pid 와 일치하는 프로세스 연결 정보만을 걸래냄
        return pid_connections
    except Exception as e:
        print(f"Error fetching network connections: {e}")
        return []


# 열린포트 번호
def get_open_ports(pid):
    try:
        connections = psutil.net_connections(kind='inet')  # IPv4 주소 체계에 기반한 연결 정보를 검색하라는 것을 나타냄
        pid_ports = [conn.laddr.port for conn in connections if
                     conn.pid == pid]  # 각 연결 정보에서 laddr.port는 로컬 주소의 포트 번호를 나타냄
        return pid_ports
    except Exception as e:
        print(f"Error fetching open ports: {e}")
        return []


# 실행

procs = get_processes()


# print_processes(procs)


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
        self.procs = get_processes()

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

        # 버튼 프레임 생성
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

        # "Security Log" button
        self.security_button = ttk.Button(button_frame, text="Security Log", command=self.create_gui)
        self.security_button.pack(side="left", padx=0)

        # "Usage Monitor" button
        self.security_button = ttk.Button(button_frame, text="Usage Monitor", command=self.run_process_monitor_app)
        self.security_button.pack(side="left", padx=0)


        # 표 스크롤바 추가
        self.scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # 표와 스크롤바 배치
        self.tree.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # 표의 이벤트 리스너 등록
        self.tree.bind("<ButtonRelease-1>", self.on_item_click)  # 좌클릭 이벤트(release)
        self.tree.bind("<Button-3>", self.show_context_menu)  # 우클릭 이벤트 리스너 등록

        # 컨텍스트 메뉴 생성 => 우클릭 하면 나타나는 메뉴
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="dll", command=self.run_load_dll_and_display_result)
        self.context_menu.add_command(label="location", command=self.run_get_process_location_and_display_result)
        self.context_menu.add_command(label="PEViewer", command=self.run_peviewer_and_display_result)
        self.context_menu.add_command(label="network info", command=self.run_get_process_network_info_result)
        self.context_menu.add_command(label="process info", command=self.run_get_process_info_result)
        self.context_menu.add_command(label="copy", command=self.copy_selected_row)
        self.context_menu.add_command(label="graph", command=self.show_graph)

        ###################################ME_11.24_검색기능_line(88~242)#############################################

        # 타이틀 프레임 추가
        title_frame = ttk.Frame(root)
        title_frame.pack(side="top", pady=5, padx=5)

        # 타이틀 레이블 추가
        title_label = ttk.Label(title_frame, text="[프로세스 검색]")
        title_label.pack(side="top")

        # 검색 프레임 추가
        self.search_frame = ttk.Frame(root)
        self.search_frame.pack(side="right", padx=10)

        # 입력 창 1
        frame1 = ttk.Frame(root)
        frame1.pack(side="top", pady=5, padx=5)
        ttk.Label(frame1, text="입력창1").pack(side="left")
        self.entry1 = ttk.Entry(frame1)
        self.entry1.pack(side="left")

        # 입력 창 2
        frame2 = ttk.Frame(root)
        frame2.pack(side="top", pady=5, padx=5)
        ttk.Label(frame2, text="입력창2").pack(side="left")
        self.entry2 = ttk.Entry(frame2)
        self.entry2.pack(side="left")
        self.entry2.configure(state='disabled')  # 초기에 entry2 비활성화

        # 검색 기준을 위한 라디오 버튼
        self.search_criteria_var = tk.StringVar(value="pid")
        criteria_frame = ttk.Frame(root)
        criteria_frame.pack(side="top", pady=5, padx=5)

        ttk.Radiobutton(criteria_frame, text="PID", variable=self.search_criteria_var, value="pid",
                        command=lambda: self.toggle_entry_state(False)).pack(side="left")
        ttk.Radiobutton(criteria_frame, text="Name", variable=self.search_criteria_var, value="name",
                        command=lambda: self.toggle_entry_state(False)).pack(side="left")
        ttk.Radiobutton(criteria_frame, text="CPU", variable=self.search_criteria_var, value="cpu_usage",
                        command=lambda: self.toggle_entry_state(True)).pack(side="left")
        ttk.Radiobutton(criteria_frame, text="Memory", variable=self.search_criteria_var, value="memory_bytes",
                        command=lambda: self.toggle_entry_state(True)).pack(side="left")

        explanation_frame = ttk.Frame(root)
        explanation_frame.pack(side="top", pady=5, padx=5)

        # 설명 레이블 추가
        explanation_label = ttk.Label(explanation_frame,
                                      text="[PID,Name] 일치 검색\n복수 검색 : 콤마로 연결\n\n[CPU,Memory] 구간검색\n구간 : 입력창1 이상 입력창2 이하")
        explanation_label.pack(side="top")

        # 상태 변수 추가
        self.is_searching = False

        # "Search" 버튼_검색실행
        self.search_button = ttk.Button(root, text="Search", command=self.search_processes)
        self.search_button.pack(side="left", padx=5)

        # "Reset" 버튼_검색취소
        self.reset_button = ttk.Button(root, text="Reset", command=self.reset_search)
        self.reset_button.pack(side="left", padx=5)

    def search_processes(self):
        # 검색 결과 유지 상태로 설정
        self.is_searching = True

        search_criteria = self.search_criteria_var.get().lower()
        user_input_1 = self.entry1.get().lower()
        user_input_2 = self.entry2.get().lower()

        if search_criteria == "pid":
            # PID를 선택한 경우, 정확한 일치 검색, 여러 PID에 대한 검색 처리
            pids_list = self.parse_multiple_pids(user_input_1)
            filtered_procs = [proc for proc in self.procs if proc['pid'] in pids_list]

        elif search_criteria == "name":
            # Name을 선택한 경우, 정확한 일치 검색
            names_list = self.parse_multiple_names(user_input_1)
            filtered_procs = [proc for proc in self.procs if
                              any(name in str(proc['name']).lower() for name in names_list)]

        elif search_criteria in ["cpu_usage"]:
            # CPU를 선택한 경우, 범위 기반 검색
            filtered_procs = [proc for proc in self.procs
                              if float(user_input_1) <= proc[search_criteria] <= float(user_input_2)]

        elif search_criteria in ["memory_bytes"]:
            # Memory를 선택한 경우, 입력값을 바이트로 변환하여 범위 검색
            user_input_1_bytes = self.parse_input(user_input_1)
            user_input_2_bytes = self.parse_input(user_input_2) if user_input_2 else None  # 입력창 2가 활성화된 경우에만 값 파싱
            filtered_procs = [proc for proc in self.procs if
                              user_input_1_bytes <= proc[search_criteria] <= user_input_2_bytes]
        else:
            print("유효하지 않은 검색 기준입니다.")
            return

        # 표 초기화
        for item in self.tree.get_children():
            self.tree.delete(item)

        # 표에 검색 결과 추가
        for proc in filtered_procs:
            values = tuple(proc[key] for key in self.procs[0].keys())  # 딕셔너리를 튜플로 변환
            self.tree.insert("", "end", values=values)

    # 주어진 문자열에서 쉼표로 구분된 다수의 pid들을 추출하여 리스트로 반환하는 함수
    def parse_multiple_pids(self, input_str):
        pids = [int(pid.strip()) for pid in input_str.split(',') if pid.strip().isdigit()]
        return pids

    # 주어진 문자열에서 쉼표로 구분된 다수의 name들을 추출하여 리스트로 반환하는 함수
    def parse_multiple_names(self, input_str, value_type=str):
        names = [name.strip() for name in input_str.split(',') if name.strip()]
        return names

    # 입력값을 바이트로 변환하는 함수
    def parse_input(self, input_str):
        units = {'KB': 1024, 'MB': 1024 ** 2, 'GB': 1024 ** 3, 'TB': 1024 ** 4, 'PB': 1024 ** 5, 'EB': 1024 ** 6}
        match = re.match(r'(\d+(\.\d+)?)\s*([KMGTPEBY]{0,2})', input_str, re.IGNORECASE)
        if match:
            value = float(match.group(1))
            unit = match.group(3).upper() if match.group(3) else ''
            return value * units.get(unit, 1)
        else:
            try:
                return float(input_str)
            except ValueError:
                return float('inf')  # 유효하지 않은 입력은 무한대로 설정

    def toggle_entry_state(self, enable_entry2):
        # 라디오 버튼 선택에 따라 entry2를 활성화 또는 비활성화
        if enable_entry2:
            self.entry2.configure(state='normal')
        else:
            self.entry2.configure(state='disabled')

    def refresh_or_reset(self):
        if self.is_searching:
            # 검색 중일 때, 검색 결과를 유지하면서 프로세스 업데이트
            self.search_processes()
        else:
            # 검색 중이 아닐 때, 초기 프로세스 목록으로 업데이트
            self.update_process_list()

    def reset_search(self):
        self.update_process_list_search(self.procs)

    def update_process_list_search(self, processes=None):
        processes = processes or self.procs
        for item in self.tree.get_children():
            self.tree.delete(item)

        for proc in processes:
            values = tuple(proc[key] for key in self.procs[0].keys())  # 딕셔너리를 튜플로 변환
            self.tree.insert("", "end", values=values)

        # 검색 결과 유지 상태 해제
        self.is_searching = False

    ###################################ME_11.24_검색기능_line(88~242)#############################################

    # "Copy" 메뉴 항목에 대한 동작 _11.27 추가
    def copy_selected_row(self):
        item = self.tree.selection()[0]  # 선택한 행의 ID 가져오기
        values = self.tree.item(item, "values")  # 선택한 행의 값(프로세스 정보) 가져오기
        selected_pid = values[0]
        selected_name = values[1]

        # 컨텍스트 메뉴 생성
        copy_menu = Menu(self.root, tearoff=0)
        copy_menu.add_command(label="pid", command=lambda: self.copy_to_clipboard(selected_pid))
        copy_menu.add_command(label="name", command=lambda: self.copy_to_clipboard(selected_name))
        copy_menu.post(self.root.winfo_pointerx(), self.root.winfo_pointery())

    # 클립보드로 복사하는 함수
    def copy_to_clipboard(self, value):
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update()

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

        start_button = ttk.Button(pkt_frame, text="패킷 캡처 시작", command=lambda: threading.Thread(target=packet_capture,
                                                                                               args=(
                                                                                               interface_entry.get(),)).start())
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
            units = {'KB': 1024, 'MB': 1024 ** 2, 'GB': 1024 ** 3, 'TB': 1024 ** 4, 'PB': 1024 ** 5, 'EB': 1024 ** 6}
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
        # print("Selected PID:", pid_value)
        return pid_value

    def get_pid(self):  # 프로세스 pid 값 받아오는 함수 int 형으로 형 변환 후에 사용해야 함
        event = None
        pid = self.on_item_click(event)
        result = int(pid)
        return result

    def run_end_process(self):
        result = end_process(self)
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("terminate processs")

        # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)

    def run_get_process_network_info_result(self):
        result = run_get_network_info(self)
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("network information")

        # 스크롤 가능한 텍스트 위젯 생성
        result_text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        result_text.insert(tk.END, result)
        result_text.pack(fill=tk.BOTH, expand=True)

    def run_get_process_info_result(self):
        result = run_get_process_info(self)
        # 실행 결과를 표시할 새 창 생성
        result_window = tk.Toplevel(self.root)
        result_window.title("process information")

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

    # 프로세스의 cpu memory 사용 그래프로 표현
    def show_graph(self):
        # 특정 PID 값
        value = self.get_pid()
        graph_pid = int(value)

        # 그래프 초기화
        fig, (ax_cpu, ax_memory) = plt.subplots(2, 1, figsize=(10, 8))
        line_cpu, = ax_cpu.plot([], [], label='CPU %')
        line_memory, = ax_memory.plot([], [], label='Memory %')

        ax_cpu.legend(loc='upper left')
        ax_memory.legend(loc='upper left')

        ax_cpu.set_ylim(0, 100)
        ax_memory.set_ylim(0, 100)
        ax_cpu.set_title('CPU Usage')
        ax_memory.set_title('Memory Usage')

        # 초기 데이터 설정
        frame = 0
        x_data = []
        cpu_percent_data = []
        memory_percent_data = []

        def update(_):
            nonlocal frame

            # 특정 PID의 메모리 사용량 가져오기
            process = psutil.Process(graph_pid)
            cpu_percent = process.cpu_percent(interval=1)
            memory_percent = process.memory_percent()

            # 데이터 추가
            x_data.append(frame)
            cpu_percent_data.append(cpu_percent)
            memory_percent_data.append(memory_percent)

            # 데이터 갱신
            line_cpu.set_xdata(x_data)
            line_memory.set_xdata(x_data)
            line_cpu.set_ydata(cpu_percent_data)
            line_memory.set_ydata(memory_percent_data)

            # 그래프 업데이트
            ax_cpu.relim()
            ax_memory.relim()
            ax_cpu.autoscale_view()
            ax_memory.autoscale_view()

            # frame 증가
            frame += 1

        # 애니메이션 생성
        ani = FuncAnimation(fig, update, frames=None, interval=1000)

        # 그래프 표시
        plt.show()

    def is_admin(self):  # 관리자권한으로 코드를 실행
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def run_as_admin(self):  # 관리자권한으로 코드를 실행
        if not self.is_admin():
            try:
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    sys.executable,
                    " ".join(sys.argv),
                    None,
                    1
                )
            except ctypes.WinError as e:
                if e.winerror == 1223:
                    pass
                else:
                    raise
            sys.exit()
        else:
            messagebox.showinfo("Success", "관리자 권한으로 실행중입니다 !")

    def read_security_event_log(self):  # 로그이벤트 읽어오기
        log_path = "Security"
        log_handle = win32evtlog.OpenEventLog(None, log_path)
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(log_handle, flags, 0)

            log_text = ""
            for event in events:
                event_time = event.TimeGenerated.Format()
                event_id = event.EventID
                description = event.StringInserts[0] if event.StringInserts else " 설명 없음"
                security_id = event.StringInserts[1] if len(event.StringInserts) > 1 else "알 수 없음"
                account_name = event.StringInserts[2] if len(event.StringInserts) > 2 else "알 수 없음"
                logon_id = event.StringInserts[4] if len(event.StringInserts) > 4 else "알 수 없음"
                logon_type = event.StringInserts[5] if len(event.StringInserts) > 5 else "알 수 없음"
                workstation_name = event.StringInserts[6] if len(event.StringInserts) > 6 else "알 수 없음"
                source_address = event.StringInserts[7] if len(event.StringInserts) > 7 else "알 수 없음"

                log_text += f"이벤트 시간: {event_time}\n"
                log_text += f"이벤트 ID: {event_id}\n"
                log_text += f"설명: {description}\n"
                log_text += f"보안 ID: {security_id}\n"
                log_text += f"계정 이름: {account_name}\n"
                log_text += f"로그온 ID: {logon_id}\n"
                log_text += f"로그온 유형: {logon_type}\n"
                log_text += f"작업 스테이션 이름: {workstation_name}\n"
                log_text += f"소스 네트워크 주소: {source_address}\n"
                log_text += "-" * 50
                log_text += "\n"
            return log_text
        except Exception as e:
            return f"이벤트 로그를 읽는 중 오류 발생: {e}"
        finally:
            win32evtlog.CloseEventLog(log_handle)

    def on_read_log_button_click(self):  # 보안로그를 출력하는 버튼 생성
        self.run_as_admin()  # self를 사용하여 메서드 호출 수정
        log_text = self.read_security_event_log()  # self를 사용하여 메서드 호출 수정
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, log_text)
        self.result_text.config(state=tk.DISABLED)

    def create_gui(self):  # 결과창 실행
        app = tk.Tk()
        app.title("Event Log Reader")

        self.result_text = scrolledtext.ScrolledText(app, width=80, height=50, wrap=tk.WORD, state=tk.DISABLED)
        self.result_text.pack(padx=10, pady=10)

        read_log_button = tk.Button(app, text="Read Log", command=self.on_read_log_button_click)
        read_log_button.pack(pady=10)

        app.mainloop()

    ###################################################################################################
    #실시간 자원 사용량 모니터링

    def configure_logging():
        # 로깅 정보 초기화
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def print_one_second_usage(app):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        separator_line = f"\n---------------- {current_time} ----------------\n"
        app["log_text"].insert(tk.END, separator_line)
        app["log_text"].yview(tk.END)

        # 1초 사용량 출력
        for pid in app["new_pids"]:
            monitor_process(app, pid)

        separator_line = "\n----------------------------------------\n"
        app["log_text"].insert(tk.END, separator_line)
        app["log_text"].yview(tk.END)

        # 1초 타이머
        if app["monitoring_active"]:
            app["timer_id"] = app["master"].after(1000, lambda: print_one_second_usage(app))

    def monitor_process(app, pid):
        try:
            # PID에 대한 CPU 및 메모리 사용량
            process = psutil.Process(pid)
            cpu_percent = round(process.cpu_percent(interval=0.05), 2)
            current_memory_usage = round(process.memory_info().rss / (1024 ** 2), 2)

            if pid in app["previous_memory_usage"]:
                memory_change = round(current_memory_usage - app["previous_memory_usage"][pid], 2)
            else:
                memory_change = 0.0

            # 사용량 정보
            log_message = (
                f"\n-------- 프로세스 리소스 사용 로그 --------\n"
                f"프로세스 PID: {pid}\n"
                f"CPU 사용량: {cpu_percent}%\n"
                f"메모리 사용량: {current_memory_usage} MB\n"
                f"메모리 변화량: {memory_change} MB\n"
            )

            app["log_text"].insert(tk.END, log_message)
            app["log_text"].yview(tk.END)

            app["previous_memory_usage"][pid] = current_memory_usage

        except psutil.NoSuchProcess as e:
            logging.error(f"PID가 {pid}인 프로세스를 찾을 수 없습니다: {e}")
        except Exception as e:
            logging.error(f"오류가 발생했습니다: {e}")

    def toggle_monitoring(app):
        if app["monitoring_active"]:
            stop_monitoring(app)
        else:
            start_monitoring(app)

    def start_monitoring(app):
        try:
            app["new_pids"] = [int(pid.strip()) for pid in app["pid_entry"].get().split(',')]
            configure_logging()

            # 현재 모니터링 중인 프로세스 중지
            if app["current_procs"]:
                stop_monitoring(app)


            app["monitoring_active"] = True
            app["start_button"]["text"] = "Pause Monitoring"
            app["stop_button"]["state"] = tk.NORMAL

            # 1초 타이머
            print_one_second_usage(app)

        except ValueError:
            logging.error("Invalid PID(s). Please enter valid integer PIDs separated by commas.")

    def stop_monitoring(app):
        # 타이머 중지 후 상태 초기화
        if app["timer_id"] is not None:
            app["master"].after_cancel(app["timer_id"])

        app["current_procs"] = []
        app["previous_memory_usage"] = {}
        app["monitoring_active"] = False
        app["start_button"]["text"] = "Start Monitoring"
        app["stop_button"]["state"] = tk.DISABLED

    def run_process_monitor_app(self):  #usage monitoring 실행 함수
        root = tk.Tk()

        app = {
            "master": root,
            "current_procs": [],
            "timer_id": None,
            "previous_memory_usage": {},
            "new_pids": [],
            "monitoring_active": False,
            "pid_entry": ttk.Entry(root),
            "start_button": ttk.Button(root, text="Start Monitoring", command=lambda: toggle_monitoring(app)),
            "stop_button": ttk.Button(root, text="Stop Monitoring", command=lambda: stop_monitoring(app),
                                      state=tk.DISABLED),
            "log_text": tk.Text(root, height=30, width=60),
        }

        app["pid_entry"].pack(pady=10)
        ttk.Label(root, text="구분점은 , 입니다").pack(pady=3)
        app["start_button"].pack(pady=10)
        app["stop_button"].pack(pady=10)
        app["log_text"].pack(pady=10)

        app["master"].title("Usage Monitoring")

        root.mainloop()


###########################################################################################################

# 바이러스 토탈 실행행
class get_VT_result:
    def __init__(self, root):
        self.root = root
        self.root.title("VirusTotal 결과")
        self.stop_flag = False  # 검사 중지 플래그 추가
        self.create_widgets()
        self.completed_tests = 0  # 완료한 검사 횟수
        self.wait_time = 60  # 초기 대기 시간 설정 (초)

    def create_widgets(self):

        # "실행 파일 해시화" 버튼 추가
        self.hash_button = tk.Button(self.root, text="전체 실행 파일 해시화", command=self.hash_executables)
        self.hash_button.pack(pady=5)
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

        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=30)
        self.result_text.pack(padx=10, pady=10)

        # 검사 실행 및 중지 버튼 추가
        self.run_button = tk.Button(self.root, text="실행", command=self.start_vt_thread)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.root, text="검사 종료", command=self.stop_vt)
        self.stop_button.pack(side=tk.RIGHT, padx=5)

        self.stop_label = tk.Label(self.root, text="", fg="red", anchor="w")
        self.stop_label.pack(side=tk.RIGHT, padx=5, fill="both")

    def hash_executables(self):
        # "실행 파일 해시화" 버튼이 클릭되었을 때 실행되는 함수
        self.result_text.delete(1.0, tk.END)  # 결과 텍스트 초기화

        try:
            processes = [psutil.Process(pid) for pid in psutil.pids()]

            with open("hash.txt", "w") as hash_file:
                for process in processes:
                    process_name = process.name()
                    md5_hash = self.get_process_md5(process)

                    print(f"프로세스: {process_name},    해시: {md5_hash}")
                    if md5_hash:
                        hash_file.write(f"{md5_hash}\n")
                    else:
                        continue
        except Exception as e:
            self.stop_label.config(text="해시화 에러!", fg="red")
        finally:
            self.stop_label.config(text="전체 실행 파일 해시화가 완료! 파일명은 hash.txt입니다.", fg="red")

    def get_process_md5(self, process):
        try:
            executable_path = process.exe()
            with open(executable_path, "rb") as file:
                content = file.read()
                md5_hash = hashlib.md5(content).hexdigest()
            return md5_hash
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError, Exception):
            return None

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

    # if __name__ == "__main__":
    # root = tk.Tk()
    # app = get_VT_result(root)
    # root.mainloop()


def main():
    root = tk.Tk()
    app = ProcessViewerApp(root)
    # root.geometry("1500x600")  # 원하는 크기로 수정
    root.mainloop()


if __name__ == "__main__":
    main()

#############################################################################################
