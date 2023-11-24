import tkinter as tk
from tkinter import ttk, scrolledtext, Entry, Label, Button, filedialog, messagebox, Menu,Scrollbar

import datetime
import psutil
import re #ME_11.24_검색기능필요

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

            procs.append({
                'pid': pid,
                'name': name,
                'create_time': create_time,
                'cpu_usage': cpu_usage,
                'cpu_affinity': cpu_affinity,
                'status': status,
                'memory': get_size(memory), 
                'memory_bytes': memory, #ME_11.24_검색기능필요
                'user': user,
            })
    return procs

def get_size(bytes):
    for i in ['', 'K', 'M', 'G', 'T', 'P', 'E']:
        if bytes < 1024:
            return f"{bytes:.2f}{i}B"
        bytes /= 1024

class ProcessViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("프로세스 뷰어")
        self.sort_direction = {}
        self.procs = get_processes()

        # 프로세스 정보를 저장할 표(Table) 생성
        self.tree = ttk.Treeview(root, columns=list(self.procs[0].keys()), show="headings")
        for key in self.procs[0].keys():
            self.sort_direction[key] = True
            self.tree.heading(key, text=key, command=lambda col=key: self.sort_table(col))
            self.tree.column(key, width=100)

        self.update_process_list()

        # 버튼 프레임 생성
        button_frame = ttk.Frame(root)
        button_frame.pack(side="top", fill="x")

        # "Refresh" button
        self.refresh_button = ttk.Button(button_frame, text="refresh", command=self.refresh_or_reset)
        self.refresh_button.pack(side="left", padx=0)

        # 표 스크롤바 추가
        self.scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # 표와 스크롤바 배치
        self.tree.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

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
        ttk.Radiobutton(criteria_frame, text="Memory", variable=self.search_criteria_var, value= "memory_bytes",
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
            filtered_procs = [proc for proc in self.procs if any(name in str(proc['name']).lower() for name in names_list)]

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
        self.update_process_list(self.procs)

    def update_process_list(self, processes=None):
        processes = processes or self.procs
        for item in self.tree.get_children():
            self.tree.delete(item)

        for proc in processes:
            values = tuple(proc[key] for key in self.procs[0].keys())  # 딕셔너리를 튜플로 변환
            self.tree.insert("", "end", values=values)

        # 검색 결과 유지 상태 해제
        self.is_searching = False

     ###################################ME_11.24_검색기능_line(88~242)#############################################

    def sort_table(self, column):
        # 정렬 방향 결정
        current_direction = self.sort_direction[column]
        new_direction = not current_direction
        self.sort_direction = {key: False for key in self.sort_direction.keys()}
        self.sort_direction[column] = new_direction

        # 표 정렬
        data = [(self.tree.set(child, column), child) for child in self.tree.get_children('')]
        data.sort(reverse=new_direction)
        for i, item in enumerate(data):
            self.tree.move(item[1], '', i)

def main():
    root = tk.Tk()
    app = ProcessViewerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
