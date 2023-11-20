#process 의 locaion
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

# 함수를 텍스트 형식으로 출력
