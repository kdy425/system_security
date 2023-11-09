#process 가 load 하는 dll 정보 가져오기
import psutil

def load_dll(pid):
    try:
        process = psutil.Process(pid)
        dll_list = process.memory_maps(grouped=False)  # grouped=False로 설정하여 리스트로 가져옴

        # DLL 목록을 텍스트로 출력
        dll_text = ""
        for dll in dll_list:
            dll_text += f' - {dll.path}\n'

        return dll_text

    except psutil.NoSuchProcess as e:
        return f"PID {pid}에 해당하는 프로세스를 찾을 수 없습니다."

    except Exception as e:
        return f"해당 프로세스가 로드하는 dll 이 없습니다.: {str(e)}"
