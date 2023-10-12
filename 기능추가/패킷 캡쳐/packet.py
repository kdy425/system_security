#packet capture 코드
import ctypes
import os
import sys
import psutil
import pyshark

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if is_admin():
    # 관리자 권한으로 실행 중일 때 수행할 작업
    def capture_network_packets(pid):
        # Find the process by PID
        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return "Process with PID {} not found.".format(pid)

        # Get the list of network connections for the process
        connections = process.connections(kind='inet')

        if not connections:
            return "No network connections found for the process with PID {}.".format(pid)

        # Create a capture filter for the process's connections
        capture_filter = ' or '.join(['(host {} and port {})'.format(conn.raddr.ip, conn.raddr.port) for conn in connections])

        try:
            # Start capturing packets
            capture = pyshark.LiveCapture(interface='eth0', display_filter=capture_filter)
            packets = []

            # Capture a limited number of packets (you can adjust this)
            for packet in capture.sniff_continuously(packet_count=10):
                packets.append(str(packet))

            # Convert captured packets to text
            packet_text = '\n'.join(['Packet {}: {}'.format(i, packet) for i, packet in enumerate(packets)])
            return packet_text

        except Exception as e:
            return "Error capturing packets: {}".format(str(e))

    pid = 23672  # Replace with the PID of the process you want to monitor
    result = capture_network_packets(pid)
    print(result)

    input("press key to exit")
else:
    # 관리자 권한으로 다시 실행
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
