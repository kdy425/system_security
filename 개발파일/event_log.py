import subprocess
import time
import logging

# 로그 설정
logging.basicConfig(filename='process.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def log_event(message):
    logging.info(message)

def run_process(command):
    try:
        log_event(f"Starting process: {command}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        log_event(f"Process exited with return code {process.returncode}")
    except Exception as e:
        log_event(f"Error running the process: {str(e)}")

if __name__ == "__main__":
    # 실행할 명령어를 설정합니다. 여기에 원하는 명령어를 넣어주세요.
    command_to_run = "your_command_here"

    # 프로세스 실행
    run_process(command_to_run)

    # 프로세스 실행 후 일정 시간 대기 (예: 5초)
    time.sleep(5)

    # 프로세스 종료
    log_event("Terminating the process")
    # 여기에서 프로세스를 종료하려면 필요한 코드를 추가하세요