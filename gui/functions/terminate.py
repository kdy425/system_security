#강제종료
import psutil

def terminate_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()
        process.wait()
        return f"프로세스 PID {pid}가 성공적으로 종료되었습니다."
    except psutil.NoSuchProcess:
        return f"프로세스 PID {pid}를 찾을 수 없습니다."
    except psutil.AccessDenied:
        return f"프로세스 PID {pid}를 종료할 권한이 없습니다."

# 사용 예제
'''
pid_to_terminate = 12345  # 종료하려는 프로세스의 PID로 교체
result = terminate_process(pid_to_terminate)
print(result)
'''