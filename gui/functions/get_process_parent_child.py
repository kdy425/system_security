#부모프로세스, 자식프로세스 출력
import psutil

def get_process_parent_child(pid):
    try:
        # 부모 프로세스 정보 가져오기
        parent_pid = psutil.Process(pid).ppid()
        parent_process = psutil.Process(parent_pid)

        # 자식 프로세스 정보 가져오기
        child_processes = psutil.Process(pid).children()

        # 현재 프로세스 이름
        process_name = psutil.Process(pid).name()

        # 부모 프로세스 이름
        parent_name = parent_process.name()

        # 자식 프로세스 이름 목록
        child_names = [child.name() for child in child_processes]

        # 출력을 준비
        process_info = f"Process PID: {pid}, Name: {process_name}\n"
        process_info += f"Parent PID: {parent_pid}, Parent Name: {parent_name}\n"
        process_info += "Child PIDs and Names:\n"
        for child, child_name in zip(child_processes, child_names):
            process_info += f"  Child PID: {child.pid}, Child Name: {child_name}\n"

        return process_info
    except psutil.NoSuchProcess:
        return "Process with PID {} not found.".format(pid)

# 예제 사용
'''
pid = 23672  # 검색하려는 프로세스의 PID로 교체
result = get_process_parent_child(pid)
print(result)
'''