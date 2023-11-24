import win32evtlog
import tkinter as tk
from tkinter import scrolledtext
import ctypes
import sys

result_text = None  # 전역 변수로 선언

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                " ".join(sys.argv),
                None,
                1
            )
        except ctypes.WinError as e:
            if e.winerror == 1223:  # 사용자가 "아니오"를 선택한 경우
                pass
            else:
                raise
        sys.exit()

def read_security_event_log():
    log_path = "Security"
    log_handle = win32evtlog.OpenEventLog(None, log_path)
    try:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(log_handle, flags, 0)

        log_text = ""
        for event in events:
            event_time = event.TimeGenerated.Format()
            event_id = event.EventID
            description = event.StringInserts[0] if event.StringInserts else " 설명 없음"
            security_id = event.StringInserts[1] if len(event.StringInserts) > 1 else "알 수 없음"
            account_name = event.StringInserts[2] if len(event.StringInserts) > 2 else "알 수 없음"
            logon_id = event.StringInserts[4] if len(event.StringInserts) > 4 else "알 수 없음"
            logon_type = event.StringInserts[5] if len(event.StringInserts) > 5 else "알 수 없음"
            workstation_name = event.StringInserts[6] if len(event.StringInserts) > 6 else "알 수 없음"
            source_address = event.StringInserts[7] if len(event.StringInserts) > 7 else "알 수 없음"

            log_text += f"이벤트 시간: {event_time}\n"
            log_text += f"이벤트 ID: {event_id}\n"
            log_text += f"설명: {description}\n"
            log_text += f"보안 ID: {security_id}\n"
            log_text += f"계정 이름: {account_name}\n"
            log_text += f"로그온 ID: {logon_id}\n"
            log_text += f"로그온 유형: {logon_type}\n"
            log_text += f"작업 스테이션 이름: {workstation_name}\n"
            log_text += f"소스 네트워크 주소: {source_address}\n"
            log_text += "\n"
        return log_text
    except Exception as e:
        return f"이벤트 로그를 읽는 중 오류 발생: {e}"
    finally:
        win32evtlog.CloseEventLog(log_handle)

def on_read_log_button_click():
    run_as_admin()
    log_text = read_security_event_log()
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, log_text)
    result_text.config(state=tk.DISABLED)

def create_gui():
    global result_text  # 전역 변수를 함수 내부에서 사용
    app = tk.Tk()
    app.title("Event Log Reader")

    result_text = scrolledtext.ScrolledText(app, width=80, height=20, wrap=tk.WORD, state=tk.DISABLED)
    result_text.pack(padx=10, pady=10)

    read_log_button = tk.Button(app, text="Read Log", command=on_read_log_button_click)
    read_log_button.pack(pady=10)

    app.mainloop()


create_gui()






