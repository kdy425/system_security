import psutil
import matplotlib.pyplot as plt
from collections import deque
import time

max_data_points = 50  # 메모리 사용량 저장하는 큐
memory_usage_data = deque(maxlen=max_data_points)  # 메모리 사용량을 저장할 큐를 설정
time_data = deque(maxlen=max_data_points)  # 시간을 저장하는 큐를 설정

plt.ion()  # 그래프가 업데이트될 때 실시간 표시
fig, ax1 = plt.subplots()

ax1.set_xlabel('시간')  # x축 시간
ax1.set_ylabel('메모리 사용량 (MB)', color='tab:blue')  # y축 메모리 사용량 (MB)

def update_memory_graph(pid):
    def inner_update():
        try:
            process = psutil.Process(pid)  # 주어진 PID의 프로세스 정보
            memory_info = process.memory_info()  # 프로세스 메모리 정보

            memory_usage = memory_info.rss / (1024 * 1024)  # 메모리 사용량 MB로 변환
            memory_usage_data.append(memory_usage)  # 메모리 사용량 큐에 추가
            time_data.append(time.strftime('%H:%M:%S'))  # 현재 시간을 큐에 추가

            ax1.clear()
            ax1.set_xlabel('시간')  # x축 레이블 설정
            ax1.set_ylabel('메모리 사용량 (MB)', color='tab:blue')  # y축 설정
            ax1.plot(time_data, memory_usage_data, color='tab:blue', label='메모리 사용량')

            # 메모리 사용량 수치 그래프 추가
            for i, v in enumerate(memory_usage_data):
                ax1.text(time_data[i], v, f'{v:.2f} MB', ha='center', va='bottom', rotation=45)


            ax1.set_ylim(0, max(memory_usage_data) * 1.2)  # 20% 범위 추가

            fig.tight_layout()  # 그래프 레이아웃 설정
            plt.xticks(rotation=45)
            plt.draw()  # 그래프 생성
            plt.pause(1)
        except psutil.NoSuchProcess:
            print(f"PID {pid}에 해당하는 프로세스를 찾을 수 없습니다.")  # 해당 PID의 프로세스를 찾을 수 없을 때
            plt.ioff()

    return inner_update
# 프로세스의 PID 입력
pid = 10072

update_func = update_memory_graph





# 그래프 출력
while True:
    update_func()
    time.sleep(3)