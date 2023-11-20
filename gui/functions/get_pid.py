#프로세스의 pid 값을 받아오는 함수

import psutil

def get_pid(process_name):
    pid = None
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            pid = process.info['pid']
            break
    return pid

process_name = "원하는 프로세스 이름"  # 예: "python.exe" 또는 "notepad.exe"
pid = get_pid(process_name)

if pid is not None:
    print(f"프로세스 '{process_name}'의 PID: {pid}")
else:
    print(f"프로세스 '{process_name}'를 찾을 수 없습니다.")
