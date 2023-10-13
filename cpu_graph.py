import psutil
import matplotlib.pyplot as plt
from collections import deque
import time


max_data_points = 50  # 최대 데이터 포인트 수를 설정
cpu_usage_data = deque(maxlen=max_data_points)
time_data = deque(maxlen=max_data_points)  # 시간 데이터를 저장하는 큐를 설정

plt.ion()  # 그래프가 업데이트될 때 실시간으로 표시
fig, ax1 = plt.subplots()


ax1.set_xlabel('시간')  # x축 시간
ax1.set_ylabel('CPU 사용률 (%)', color='tab:blue')  # y축 CPU 사용률 (%)

def update_cpu_graph(pid):
    def inner_update():
        try:
            process = psutil.Process(pid)  # 주어진 PID를 가진 프로세스 정보
            cpu_percent = process.cpu_percent()  # 프로세스의 CPU 사용률

            cpu_usage_data.append(cpu_percent)  # CPU 사용률 데이터를 큐에 추가
            time_data.append(time.strftime('%H:%M:%S'))  # 현재 시간을 큐에 추가

            ax1.clear()  # 그래프를 지웁니다.
            ax1.set_xlabel('시간')  # x축 레이블 설정
            ax1.set_ylabel('CPU 사용률 (%)', color='tab:blue')  # y축 레이블 설정
            ax1.plot(time_data, cpu_usage_data, color='tab:blue', label='CPU 사용률')

            ax1.set_ylim(0, 100)  # CPU 사용률 0%에서 100% 사이로 표시

            fig.tight_layout()  # 그래프 레이아웃을 조정
            plt.xticks(rotation=45)  # x축 레이블의 텍스트를 45도 회전하여 가독성을 높입니다.
            plt.draw()  # 그래프 생성
            plt.pause(0.01)
        except psutil.NoSuchProcess:
            print(f"PID {pid}에 해당하는 프로세스를 찾을 수 없습니다.")  # 해당 PID의 프로세스를 찾을 수 없을 때 메시지를 출력
            plt.ioff()

    return inner_update

# 프로세스의 PID 입력
pid = 12216

# CPU 사용률 그래프 업데이트 함수 선언
update_func = update_cpu_graph(pid)

# 그래프를 출력
while True:
    update_func()  # CPU 사용률 그래프를 업데이트
    time.sleep(3)