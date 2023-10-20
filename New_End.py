import psutil
import time

def monitor_processes():
    executing_processes = set()  

    while True:
        current_processes = psutil.pids()

        # 새로운 프로세스
        new_processes = [pid for pid in current_processes if pid not in executing_processes]
        for pid in new_processes:
            try:
                process = psutil.Process(pid)
                print(f"새로운 프로세스: PID={pid}, 이름={process.name()}, 상태={process.status()}")
            except psutil.NoSuchProcess:

                pass

        # 종료된 프로세스
        terminated_processes = [pid for pid in executing_processes if pid not in current_processes]
        for pid in terminated_processes:
            try:
                process = psutil.Process(pid)
                print(f"종료된 프로세스: PID={pid}, 이름={process.name()}, 상태={process.status()}")
            except psutil.NoSuchProcess:

                pass

        # 실행중인 프로세스 목록을 업데이트
        executing_processes = set(current_processes)


        time.sleep(3)


monitor_processes()