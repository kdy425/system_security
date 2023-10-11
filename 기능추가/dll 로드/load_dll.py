#프로세스가 로딩 하고 있는 dll 목록 출력(pid 따로 입력)

import psutil

def load_dll(pid):
    try:
        process = psutil.Process(pid)

        # 프로세스가 로딩하고 있는 DLL 목록
        dll_list = process.memory_maps(grouped=False)  # grouped=False로 설정하여 리스트로 가져옴

        # DLL 목록을 출력
        for dll in dll_list:
            print(f' - {dll.path}')

    except psutil.NoSuchProcess as e:
        print(f"PID {pid}에 해당하는 프로세스를 찾을 수 없습니다.")

    except Exception as e:
        print(f"오류 발생: {str(e)}")


pid = 48540  # 원하는 PID
load_dll(pid)

