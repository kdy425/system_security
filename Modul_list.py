import psutil

def list_modules(PID):
    try:
        process = psutil.Process(PID)
        modules = process.memory_maps()
        print(f"모듈 : ")
        for module in modules:

            if module.path:
                print({module.path})
    except Exception as e:
        print(f"에러 발생 : {e}")

if __name__ == "__main__":
    PID = int(input(" PID를 입력하세요 : "))
    list_modules(PID)
