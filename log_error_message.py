import subprocess
import re
import psutil


running_processes = []

for p in psutil.process_iter(attrs=['pid', 'cmdline']):
    with p.oneshot():
        if p.info.get('cmdline'):
            running_processes.append(p)

# 표준출력에서 로그 메시지 식별
log_pattern = re.compile(r'\[LOG\](.*)')

# 모든 프로세스에 대한 로그 및  오류 메시지 출력
for process in running_processes:
    try:
        # 프로세스 실행 명령어 (cmdline)를 문자열로 조합
        cmdline = ' '.join(process.info['cmdline'])


        sub_process = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)


        pid = process.info['pid']

        printed_pid = False  # PID가 한 번만 출력

        # 로그 메시지 출력
        stdout = list(sub_process.stdout)
        if stdout:
            for line in stdout:
                if not printed_pid:
                    print(f"[PID {pid}] 로그 메시지:")
                    printed_pid = True
                match = log_pattern.match(line)
                if match:
                    print(match.group(1), end='')

        # 오류 메시지 출력
        stderr = list(sub_process.stderr)
        if stderr:
            for line in stderr:
                if not printed_pid:
                    print(f"[PID {pid}] 오류 메시지:")
                    printed_pid = True
                print(line, end='')

    except (subprocess.CalledProcessError, FileNotFoundError):
        # 프로세스를 실행할 수 없는 경우 또는 에러가 발생한 경우 처리
        print(f"[PID {process.info['pid']}] 프로세스를 실행할 수 없음")
