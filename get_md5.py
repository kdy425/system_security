import psutil
import hashlib

def get_process_md5(process):
    try:
        executable_path = process.exe()
        with open(executable_path, "rb") as file:
            content = file.read()
            md5_hash = hashlib.md5(content).hexdigest() #md5 대신 다른 알고리즘 삽입하여 해시 알고리즘 변경 가능
        return md5_hash
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError):
        return None

def main():
    # 현재 실행 중인 모든 프로세스 가져오기
    processes = [psutil.Process(pid) for pid in psutil.pids()]

    with open("hash.txt", "w") as hash_file:
        for process in processes:
            # 프로세스 이름과 MD5 해시 가져오기
            process_name = process.name()
            md5_hash = get_process_md5(process)

            # 출력 및 파일에 저장
            print(f"프로세스: {process_name}, MD5 해시: {md5_hash}")
            if md5_hash:
                hash_file.write(f"{md5_hash}\n")
            else:
                continue
                #hash_file.write(f"{process_name}: error_____________________________________ \n") #에러 메시지 출력

if __name__ == "__main__":
    main()
