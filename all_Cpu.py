import psutil
import matplotlib.pyplot as plt
from collections import deque
import time

max_data_points = 50
memory_usage_data = deque(maxlen=max_data_points)

plt.ion()
fig, ax1 = plt.subplots()
ax1.set_xlabel('시간')
ax1.set_ylabel('전체 메모리 사용률 (%)', color='tab:blue')


def update_total_memory_graph():
    memory_percent = psutil.virtual_memory().percent  # 전체 메모리 사용률
    memory_usage_data.append(memory_percent)
    ax1.clear()
    ax1.set_xlabel('시간')
    ax1.set_ylabel('전체 메모리 사용률 (%)', color='tab:blue')
    ax1.plot(memory_usage_data, color='tab:blue', label='전체 메모리 사용률')
    max_value = max(memory_usage_data) * 1.2
    ax1.set_ylim(0, max_value)
    ax1.set_yticks(range(0, int(max_value) + 1, 10))
    fig.tight_layout()

def update_memory_graph():
    try:
        while True:
            update_total_memory_graph()
            plt.draw()
            plt.pause(1)
    except KeyboardInterrupt:
        pass

plt.ioff()
plt.show()
update_memory_graph()