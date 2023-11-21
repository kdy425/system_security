import tkinter as tk
from tkinter import scrolledtext, Entry, Label, Button, filedialog
import urllib.request
import urllib.parse
import json
import time
import threading

class get_VT_result:
    def __init__(self, root):
        self.root = root
        self.root.title("VirusTotal 결과")
        self.stop_flag = False  # 검사 중지 플래그 추가
        self.create_widgets()
        self.completed_tests = 0  # 완료한 검사 횟수
        self.wait_time = 60  # 초기 대기 시간 설정 (초)

    def create_widgets(self):
        # API 키를 입력 받을 Entry 위젯 추가
        self.api_key_label = Label(self.root, text="VIRUS TOTAL 접속 API키")
        self.api_key_label.pack()

        self.api_key_entry = Entry(self.root, width=40)
        self.api_key_entry.pack(pady=5)

        # 파일을 선택할 버튼과 선택된 파일 경로를 표시할 레이블 추가
        self.file_path_label = Label(self.root, text="대조할 정보 파일 선택")
        self.file_path_label.pack(pady=5)

        self.select_file_button = Button(self.root, text="파일 선택", command=self.browse_file)
        self.select_file_button.pack(pady=5)

        # 파일 선택 설명 레이블 추가
        self.file_desc_label = Label(self.root, text="이 검사는 VirusTotal의 데이터베이스를 이용합니다.\n"
                                                     "무료 계정의 경우 1분에 1번의 검사를 실행할 수 있으며, 1번 검사에 4개의 값을 검사합니다.")
        self.file_desc_label.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20)
        self.result_text.pack(padx=10, pady=10)

        # 검사 실행 및 중지 버튼 추가
        self.run_button = tk.Button(self.root, text="실행", command=self.start_vt_thread)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.root, text="검사 종료", command=self.stop_vt)
        self.stop_button.pack(side=tk.RIGHT, padx=5)

        self.stop_label = tk.Label(self.root, text="", fg="red", anchor="w")
        self.stop_label.pack(side=tk.RIGHT, padx=5, fill="both")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_label.config(text=f"선택된 파일: {file_path}")

    def get_virus_total(self, api_key, file_path):
        HOST = 'www.virustotal.com'
        SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
        REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

        fields = [('apikey', api_key)]

        with open(file_path, 'r') as txtf:
            count = 0
            while True:
                line = txtf.readline().strip('\n')
                if not line:
                    break
                
                if self.stop_flag:  # 검사 중지 플래그 확인
                    self.stop_flag = False  # 플래그 초기화
                    self.stop_label.config(text="검사가 종료되었습니다.", fg="red")
                    return  # 검사가 중지되면 함수를 종료하여 결과 창이 닫히지 않도록 함

                parameters = {'resource': line, 'apikey': api_key}
                data = urllib.parse.urlencode(parameters).encode('utf-8')
                req = urllib.request.Request(REPORT_URL, data)
                response = urllib.request.urlopen(req)
                data = response.read()
                data = json.loads(data)

                md5 = data.get('md5', {})
                scan = data.get('scans', {})
                keys = scan.keys()

                result = "\n"
                result += "========================================================================="
                if not md5:
                    result += "\n !!!!!!!!! 다음 백신 엔진에 검색한 결과, 일치하는 항목이 없습니다. !!!!!!!!! "
                else:
                    result += '\n해시 : ' + str(md5)
                result += "\n=========================================================================="
                for key in keys:
                    if key in ['AhnLab-V3', 'ALYac', 'ViRobot']:
                        result += '\n%-20s : %s' % (key, scan[key]['result'])

                result += "\n++++++++++++++++" + str(md5) + " 검사 완료 +++++++++++++++++"
                
                # GUI 업데이트
                self.result_text.insert(tk.END, result)
                self.result_text.update()
                count += 1

                if count == 4:  # 4개의 파일 검사를 마치면 1분 대기 후 count 초기화
                    self.completed_tests += 1
                    remaining_time = self.wait_time
                    while remaining_time > 0:
                        self.stop_label.config(text=f"{self.completed_tests}번째 검사를 완료했습니다. "
                                                    f"다음 무료 검사를 위해 1분 대기 중입니다. "
                                                    f"(남은 시간: {remaining_time}초)", fg="gray")
                        time.sleep(1)
                        remaining_time -= 1
                    count = 0

        # 검사가 완료되면 라벨 업데이트
        self.stop_label.config(text="검사가 완료되었습니다.", fg="green")

    def start_vt_thread(self):
        # 버튼 클릭시 실행되는 함수를 스레드로 실행
        self.stop_label.config(text="검사가 실행 중입니다.", fg="blue")
        self.stop_flag = False  # 검사 중지 플래그 초기화
        api_key = self.api_key_entry.get()
        file_path = self.file_path_label.cget("text").replace("선택된 파일: ", "")

        # 실행 전 결과 텍스트 초기화
        self.result_text.delete(1.0, tk.END)

        # 스레드 시작
        vt_thread = threading.Thread(target=self.get_virus_total, args=(api_key, file_path))
        vt_thread.start()

    def stop_vt(self):
        # 검사 중지 버튼 클릭 시 호출되는 함수
        self.stop_flag = True
        self.stop_label.config(text="검사가 중지되었습니다. 대기시간 계산과 관계없이 바로 창을 닫아도 무방합니다.", fg="orange")

if __name__ == "__main__":
    root = tk.Tk()
    app = get_VT_result(root)
    root.mainloop()
