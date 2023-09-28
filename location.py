import psutil

def get_process_location(pid):
    try:
        process = psutil.Process(pid)
        exe = process.exe()
        return exe
    except psutil.NoSuchProcess:
        return f"Process with PID {pid} not found."
    except psutil.AccessDenied:
        return f"Access denied to process with PID {pid}."
    except Exception as e:
        return str(e)

# 특정 PID를 지정하여 프로그램의 위치를 얻습니다.
pid_to_check = 8992  # 원하는 PID를 여기에 입력하세요.
location = get_process_location(pid_to_check)
print(f"프로세스 {pid_to_check}의 위치: {location}")
