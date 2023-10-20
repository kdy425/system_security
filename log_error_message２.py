import psutil
import os


def find_log_files(process):
    try:
        pid = process.pid
        process_name = process.name()

        # 이벤트, 오류 및 로그 파일을 저장하는 경로 설정
        event_log_path = f"/path/to/logs/{process_name}_event.log"
        error_log_path = f"/path/to/logs/{process_name}_error.log"
        standard_log_path = f"/path/to/logs/{process_name}_log.log"

        # 파일들을 읽어내기
        event_log_content = read_log_file(event_log_path)
        error_log_content = read_log_file(error_log_path)
        standard_log_content = read_log_file(standard_log_path)

        if event_log_content:
            print(f"프로세스 PID: {pid}, 이름: {process_name}")
            print("이벤트 로그 내용:")
            print(event_log_content)

        if error_log_content:
            print(f"프로세스 PID: {pid}, 이름: {process_name}")
            print("오류 로그 내용:")
            print(error_log_content)

        if standard_log_content:
            print(f"프로세스 PID: {pid}, 이름: {process_name}")
            print("표준 로그 내용:")
            print(standard_log_content)

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass


def read_log_file(log_path):
    try:
        with open(log_path, "r") as log_file:
            return log_file.read()
    except (FileNotFoundError, PermissionError):
        return ""


for process in psutil.process_iter(['pid', 'name']):
    find_log_files(process)