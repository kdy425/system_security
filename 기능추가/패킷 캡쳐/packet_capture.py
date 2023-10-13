#packet capture with gui
import tkinter as tk
from tkinter import ttk, Scrollbar
import threading
from scapy.all import sniff

# 패킷 캡처 함수
def packet_capture(interface):
    sniff(iface=interface, prn=lambda x: pkt_listbox.insert(tk.END, str(x)))

# GUI 생성
app = tk.Tk()
app.title("프로세스 뷰어 및 패킷 캡처")

# Set the window size
app.geometry("700x400")  # 창 크기 조절

# 패킷 캡처
pkt_frame = ttk.Frame(app)
pkt_frame.pack(fill="both", expand=True)  # 창 채우기

interface_entry = ttk.Entry(pkt_frame)
interface_entry.grid(row=0, column=1)

start_button = ttk.Button(pkt_frame, text="패킷 캡처 시작", command=lambda: threading.Thread(target=packet_capture, args=(interface_entry.get(),)).start())
start_button.grid(row=0, column=2)

# 패킷 캡처 결과에 스크롤바 추가
pkt_listbox = tk.Listbox(pkt_frame)
pkt_listbox.grid(row=1, column=0, columnspan=3, sticky="nsew")  # Make the listbox expand


pkt_frame.columnconfigure(0, weight=1)
pkt_frame.rowconfigure(1, weight=1)

# 스크롤바 추가
scrollbar = Scrollbar(pkt_frame, orient=tk.VERTICAL)
scrollbar.config(command=pkt_listbox.yview)
scrollbar.grid(row=1, column=3, sticky="ns")

pkt_listbox.config(yscrollcommand=scrollbar.set)

app.mainloop()
