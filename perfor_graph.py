import psutil
import matplotlib.pyplot as plt
from collections import deque
import time


max_data_points = 50
cpu_usage_data = deque(maxlen=max_data_points)
memory_usage_data = deque(maxlen=max_data_points)

# 그래프 초기화
plt.ion()
fig, ax1 = plt.subplots()
ax2 = ax1.twinx()
ax1.set_xlabel('시간')
ax1.set_ylabel('CPU 사용률 (%)', color='tab:blue')
ax2.set_ylabel('메모리 사용량 (MB)', color='tab:red')


def update_graph(pid):
    def inner_update():
        try:
            process = psutil.Process(pid)
            cpu_percent = process.cpu_percent(interval=1)
            memory_info = process.memory_info()

            cpu_usage_data.append(cpu_percent)
            memory_usage_data.append(memory_info.rss / (1024 * 1024))

            ax1.clear()
            ax1.set_xlabel('시간')
            ax1.set_ylabel('CPU 사용률 (%)', color='tab:blue')
            ax2.set_ylabel('메모리 사용량 (MB)', color='tab:red')
            ax1.plot(cpu_usage_data, color='tab:blue', label='CPU 사용률')
            ax2.plot(memory_usage_data, color='tab:red', label='메모리 사용량')

            ax1.set_ylim(0, max(cpu_usage_data) * 1.2)  # CPU 사용률
            ax2.set_ylim(0, max(memory_usage_data) * 1.2)  # 메모리 사용량

            fig.tight_layout()
            plt.draw()
            plt.pause(0.01)
        except psutil.NoSuchProcess:
            print(f"PID {pid}에 해당하는 프로세스를 찾을 수 없습니다.")
            plt.ioff()

    return inner_update

# 프로세스의 PID를 입력
pid = 12216


update_func = update_graph(pid)

# 그래프 출력
while True:
    update_func()
    time.sleep(3)