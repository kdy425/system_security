import psutil

def API(pid):
    try:
        process = psutil.Process(pid)
        connections = process.connections(kind='all') #kind 변수를 통해 더 세부적인 연결 분류 가능

        print(f"프로세스 ID: {pid}")
        print(f"프로세스 이름: {process.name()}")
        print(f"프로세스 상태: {process.status()}\n")

        if connections:
            print("호출된 시스템 호출 및 API 목록:")
            for connect in connections:
                print(f"  로컬 주소: {connect.laddr}")
                if connect.status is not "NONE":   #none 값이 나올 경우 왜 그런 값이 나온지 출력하는 기능 추가
                    print(f"   호출된 API: {connect.status}")
                else:
                    print("   호출된 API: 정보 없음 (시스템 호출이나 API가 없거나 연결이 아직 활성화되지 않았습니다)")
                print()
        else:
            print("호출된 시스템 호출 및 API가 없습니다.")

        Count = len(connections)
        print(f"* 추정 시스템 호출 수: {Count} *")
        print("-" * 50)
    except psutil.NoSuchProcess:                #이미 종료되었거나 삭제된 프로세스 or pid라이브러리에 존재하지않는 프로세스
        print(f"프로세스 ID {pid}에 해당하는 프로세스를 찾을 수 없습니다.")


for proc in psutil.process_iter(['pid']):
    try:
        pid = proc.info['pid']
        API(pid)
    except (psutil.AccessDenied, psutil.ZombieProcess):
        pass
