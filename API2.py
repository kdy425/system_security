import psutil
import win32con
import win32api
import win32process

def get_api_calls(process_id):
    try:
        # 프로세스 존재 여부 확인
        if not psutil.pid_exists(process_id):
            print(f"프로세스 (PID: {process_id})가 이미 종료되었습니다.")
            return set()

        # 프로세스에 대한 핸들
        process_handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
            False,
            process_id,
        )

        # 핸들 권한 확인
        if not process_handle:
            raise Exception("프로세스 핸들을 열 수 없습니다.")

        # 프로세스 연결된 모듈 목록
        modules = win32process.EnumProcessModules(process_handle)

        # 모듈 목록 확인
        if not modules:
            raise Exception("프로세스에 연결된 모듈 목록을 가져올 수 없습니다.")

        # API 목록 저장 공간 생성
        api_calls = set()

        # 각 모듈에서 API 목록을 추출
        for module in modules:
            module_name = win32process.GetModuleFileNameEx(process_handle, module)
            print(f"모듈: {module_name}")

            # 모듈에 연결된 함수 목록
            functions = win32process.EnumProcessModules(module)

            # 함수 목록에서 API 목록 추출
            for function in functions:
                api_calls.add(function)


        return api_calls

    except Exception as e:
        print(f"오류 발생: {e}")
        return set()

# 모든 실행 중인 프로세스 목록
all_processes = psutil.process_iter(attrs=['pid', 'name'])

# 프로세스별로 API 호출 목록 출력
for process in all_processes:
    try:

        pid = process.info['pid']
        name = process.info['name']


        current_process = psutil.Process(pid)

        # 프로세스의 시스템 호출 내용
        system_calls = current_process.connections()

        # 시스템 호출 내용 출력
        if system_calls:
            print(f"Process PID: {pid}, Name: {name}")
            for conn in system_calls:
                print(f"  Family: {conn.family}, Type: {conn.type}, Local Address: {conn.laddr}, Remote Address: {conn.raddr}")
            print("-" * 50)

        # 프로세스의 API 호출 목록 출력
        api_calls = get_api_calls(pid)
        if api_calls:
            print(f"API 호출 목록:")
            for api_call in api_calls:
                print(api_call)
            print("-" * 50)

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # 예외 처리: 프로세스 정보에 접근할 수 없거나 더 이상 존재하지 않는 경우
        pass