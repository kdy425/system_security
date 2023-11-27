import psutil
import logging
import tkinter as tk
from tkinter import ttk

class ProcessMonitorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("프로세스 모니터")
        self.master.geometry("600x500")  # 창 크기

        self.create_widgets()
        self.current_procs = []  # 현재 모니터링 중인 프로세스 PID
        self.timer_id = None  # 타이머 식별자
        self.previous_memory_usage = {}  # 이전 메모리 사용량
        self.new_pids = []  # 입력받은 새로운 프로세스 PID
        self.monitoring_active = False  # 모니터링 활성화 여부 플래그

    def create_widgets(self):
        # GUI 위젯 생성
        ttk.Label(self.master, text="Enter the PIDs of the processes to monitor (comma-separated):").pack(pady=10)
        self.pid_entry = ttk.Entry(self.master)
        self.pid_entry.pack(pady=10)
        self.start_button = ttk.Button(self.master, text="Start Monitoring", command=self.toggle_monitoring)
        self.start_button.pack(pady=10)
        self.stop_button = ttk.Button(self.master, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(pady=10)
        self.log_text = tk.Text(self.master, height=30, width=60)
        self.log_text.pack(pady=10)

    def toggle_monitoring(self):
        if self.monitoring_active:
            self.stop_monitoring()
        else:
            self.start_monitoring()

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
            self.monitoring_active = True
            self.start_button["text"] = "Pause Monitoring"
            self.stop_button["state"] = tk.NORMAL

            # 1초마다 정보 출력 타이머 시작
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
        if self.monitoring_active:
            self.timer_id = self.master.after(1000, self.print_one_second_usage)

    def stop_monitoring(self):
        # 현재 실행 중인 타이머 중지 후 상태 초기화
        if self.timer_id is not None:
            self.master.after_cancel(self.timer_id)

        self.current_procs = []
        self.previous_memory_usage = {}
        self.monitoring_active = False
        self.start_button["text"] = "Start Monitoring"
        self.stop_button["state"] = tk.DISABLED

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
                f"\n-------- 프로세스 리소스 사용 로그 --------\n"
                f"프로세스 PID: {pid}\n"
                f"CPU 사용량: {cpu_percent}%\n"
                f"메모리 사용량: {current_memory_usage} MB\n"
                f"메모리 변화량: {memory_change} MB\n"
            )

            self.log_text.insert(tk.END, log_message)
            self.log_text.yview(tk.END)

            self.previous_memory_usage[pid] = current_memory_usage

        except psutil.NoSuchProcess as e:
            logging.error(f"PID가 {pid}인 프로세스를 찾을 수 없습니다: {e}")
        except Exception as e:
            logging.error(f"오류가 발생했습니다: {e}")

def configure_logging():
    # 로깅 정보 초기화
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    # 메인 행동
    root = tk.Tk()
    app = ProcessMonitorApp(root)
    root.mainloop()
