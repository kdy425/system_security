import psutil
import matplotlib.pyplot as plt
from collections import deque

max_data_points = 50
cpu_usage_data = deque(maxlen=max_data_points)

plt.ion()
fig, ax1 = plt.subplots()
ax1.set_xlabel('시간')
ax1.set_ylabel('전체 CPU 사용률 (%)', color='tab:blue')


def update_total_cpu_graph():
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_usage_data.append(cpu_percent)
    ax1.clear()
    ax1.set_xlabel('시간')
    ax1.set_ylabel('전체 CPU 사용률 (%)', color='tab:blue')
    ax1.plot(cpu_usage_data, color='tab:blue', label='전체 CPU 사용률')

    ax1.set_ylim(0, 1.0)
    ax1.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    fig.tight_layout()


def display_cpu_usage_graph():
    try:
        while True:
            update_total_cpu_graph()
            plt.draw()
            plt.pause(1)
    except KeyboardInterrupt:
        pass

    plt.ioff()
    plt.show()


display_cpu_usage_graph()
