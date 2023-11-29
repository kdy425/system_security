import psutil
import logging
import tkinter as tk
from tkinter import ttk
from datetime import datetime

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

    # 다음 1초 동안 정보 불러오기
    if app["monitoring_active"]:
        app["timer_id"] = app["master"].after(1000, lambda: print_one_second_usage(app))

def monitor_process(app, pid):
    try:
        # PID에 대한 CPU 및 메모리 사용량 불러오기
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

        # 현재 모니터링 중인 프로세스가 있다면 중지
        if app["current_procs"]:
            stop_monitoring(app)

        # 구분선에 현재 시간 추가

        # 사용량 출력 시작
        app["monitoring_active"] = True
        app["start_button"]["text"] = "Pause Monitoring"
        app["stop_button"]["state"] = tk.NORMAL

        # 1초마다 정보 출력 타이머 시작
        print_one_second_usage(app)

    except ValueError:
        logging.error("Invalid PID(s). Please enter valid integer PIDs separated by commas.")

def stop_monitoring(app):
    # 현재 실행 중인 타이머 중지 후 상태 초기화
    if app["timer_id"] is not None:
        app["master"].after_cancel(app["timer_id"])

    app["current_procs"] = []
    app["previous_memory_usage"] = {}
    app["monitoring_active"] = False
    app["start_button"]["text"] = "Start Monitoring"
    app["stop_button"]["state"] = tk.DISABLED

def run_process_monitor_app():
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
        "stop_button": ttk.Button(root, text="Stop Monitoring", command=lambda: stop_monitoring(app), state=tk.DISABLED),
        "log_text": tk.Text(root, height=30, width=60),
    }

    app["pid_entry"].pack(pady=10)
    app["start_button"].pack(pady=10)
    app["stop_button"].pack(pady=10)
    app["log_text"].pack(pady=10)

    root.mainloop()

# 실행

