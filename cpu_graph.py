import psutil
import matplotlib.pyplot as plt
from collections import deque
import time

max_data_points = 50
cpu_usage_data = deque(maxlen=max_data_points)
time_data = deque(maxlen=max_data_points)

plt.ion()
fig, ax1 = plt.subplots()

ax1.set_xlabel('시간')
ax1.set_ylabel('CPU 사용률 (%)', color='tab:blue')

def update_cpu_graph(pid):
    def inner_update():
        try:
            process = psutil.Process(pid)
            cpu_percent = process.cpu_percent(interval=1)

            cpu_usage_data.append(cpu_percent)
            time_data.append(time.strftime('%H:%M:%S'))

            ax1.clear()
            ax1.set_xlabel('시간')
            ax1.set_ylabel('CPU 사용률 (%)', color='tab:blue')
            ax1.plot(time_data, cpu_usage_data, color='tab:blue', label='CPU 사용률')

            # y 축 범위를 자동으로 조정
            ax1.relim()
            ax1.autoscale_view()

            fig.tight_layout()
            plt.xticks(rotation=45)
            plt.draw()
            plt.pause(0.01)
        except psutil.NoSuchProcess:
            print(f"PID {pid}에 해당하는 프로세스를 찾을 수 없습니다.")
            plt.ioff()

    return inner_update

# 프로세스의 PID
pid = 26752

update_func = update_cpu_graph(pid)

while True:
    update_func()
    time.sleep(2)
