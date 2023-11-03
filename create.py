import psutil
import datetime


pid = int(input(" PID를 입력하세요:  "))

try:
    process = psutil.Process(pid)

    # 프로세스 생성 시간
    create_time = process.create_time()

    # 시간 단위 변환
    create_time_datetime = datetime.datetime.fromtimestamp(create_time)
    formatted_create_time = create_time_datetime.strftime("%Y-%m-%d %H:%M:%S")

    print(f" PID {pid} 의 생성된 시간: {formatted_create_time}")

except psutil.NoSuchProcess:
    print(f"해당 PID {pid}가 존재하지 않는다.")
except Exception as e:
    print(f"에러 발생 : {str(e)}")
