import psutil

#파일 저장 경로 출력 함수
#특정 프로세스의 pid 변수를 받아 해당 프로세스의 파일 저장 경로를 송출
def get_process_location(pid): #pid 변수를 받음
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

pid = 8992  # pid값 지정; 추후 process_viewer.py에 삽입하여 자동 할당 받도록 해야 함; 
location = get_process_location(pid) #get_process_location()함수 실행
print(f"프로세스 {pid}의 위치: {location}") #파일 경로 (get_process_location(pid) 리턴값 출력)