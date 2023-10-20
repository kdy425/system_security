import psutil
import matplotlib.pyplot as plt
from collections import deque
import time

max_data_points = 50  # 메모리 사용량 저장
memory_usage_data = deque(maxlen=max_data_points)  # 메모리 사용량을 저장
time_data = deque(maxlen=max_data_points)  # 시간을 저장

plt.ion()
fig, ax1 = plt.subplots()

ax1.set_xlabel('시간')  # x축 시간
ax1.set_ylabel('메모리 사용량 (MB)', color='tab:blue')  # y축 메모리 사용량

def update_memory_graph(pid):
    def inner_update():
        try:
            process = psutil.Process(pid)  # 주어진 PID의 프로세스 정보
            memory_info = process.memory_info()  # 프로세스 메모리 정보

            memory_usage = memory_info.rss / (1024 * 1024)
            memory_usage_data.append(memory_usage)
            time_data.append(time.strftime('%H:%M:%S'))

            ax1.clear()
            ax1.set_xlabel('시간')  # x축 설정
            ax1.set_ylabel('메모리 사용량 (MB)', color='tab:blue')  # y축 설정
            ax1.plot(time_data, memory_usage_data, color='tab:blue', label='메모리 사용량')

            # 메모리 사용량 수치 그래프
            for i, v in enumerate(memory_usage_data):
                ax1.text(time_data[i], v, f'{v:.2f} MB', ha='center', va='bottom', rotation=45)

            ax1.set_ylim(0, max(memory_usage_data) * 1.2)

            fig.tight_layout()
            plt.xticks(rotation=45)
            plt.draw()
            plt.pause(1)
        except psutil.NoSuchProcess:
            print(f"PID {pid}에 해당하는 프로세스를 찾을 수 없습니다.")
            plt.ioff()

    return inner_update

# 프로세스의 PID
pid = 7044

update_func = update_memory_graph(pid)


while True:
    update_func()
    time.sleep(3)
