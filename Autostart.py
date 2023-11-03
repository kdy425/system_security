import psutil
import winreg


def get_startup_process():
    key = winreg.HKEY_CURRENT_USER
    subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"  #재부팅시 자동실행되는 구분키
    programs = []

    try:
        with winreg.OpenKey(key, subkey) as regkey:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(regkey, i)
                    programs.append((name, value))
                    i += 1
                except OSError:
                    break
    except Exception as e:
        pass

    return programs

if __name__ == "__main__":
    running_processes = [p.info for p in psutil.process_iter(attrs=['pid', 'name'])]

    startup_programs = get_startup_process()

    print("부팅 시 자동으로 실행되는 프로세스 목록:")
    for name, path in startup_programs:
        for process in running_processes:
            if name in process['name']:
                print(f"프로세스 이름: {process['name']}, PID: {process['pid']}, 경로: {path}")
