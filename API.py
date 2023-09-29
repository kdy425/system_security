import psutil

def estimate_syscalls(pid):
    try:
        process = psutil.Process(pid)
        connections = process.connections(kind='all')

        print(f"프로세스 ID: {pid}")
        print(f"프로세스 이름: {process.name()}")
        print(f"프로세스 상태: {process.status()}\n")

        if connections:
            print("호출된 시스템 호출 및 API 목록:")
            for conn in connections:
                print(f"  로컬 주소: {conn.laddr}")
                if conn.status is not "NONE":
                    print(f"   호출된 API: {conn.status}")
                else:
                    print("   호출된 API: 정보 없음 (시스템 호출이나 API가 없거나 연결이 아직 활성화되지 않았습니다)")
                print()
        else:
            print("호출된 시스템 호출 및 API가 없습니다.")

        estimated_syscalls = len(connections)
        print(f"* 추정 시스템 호출 수: {estimated_syscalls} *")
        print("-" * 50)
    except psutil.NoSuchProcess:
        print(f"프로세스 ID {pid}에 해당하는 프로세스를 찾을 수 없습니다.")

for proc in psutil.process_iter(['pid']):
    try:
        pid = proc.info['pid']
        estimate_syscalls(pid)
    except (psutil.AccessDenied, psutil.ZombieProcess):
        pass
