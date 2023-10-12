#get network protocol and local, remote address
import psutil

def get_TCP_IP_connection_by_process(pid):
    try:
        process = psutil.Process(pid)
        connections = process.connections(kind='inet')

        if not connections:
            return "No network connections found for the process with PID {}.".format(pid)

        protocol_names = {
            1: "icmp",
            6: "tcp",
            17: "udp",
            41: "ipv6",
            47: "gre",
            50: "esp",
            51: "ah",
            132: "sctp",
            # 다른 프로토콜 번호와 이름을 추가할 수 있습니다.
        }

        network_info = []
        for conn in connections:
            protocol = protocol_names.get(conn.type, "unknown")
            local_address = f"{conn.laddr.ip if conn.laddr else 'N/A'}:{conn.laddr.port if conn.laddr else 'N/A'}"
            remote_address = f"{conn.raddr.ip if conn.raddr else 'N/A'}:{conn.raddr.port if conn.raddr else 'N/A'}"
            connection_info = {
                "protocol": protocol,
                "local_address": local_address,
                "remote_address": remote_address,
            }
            network_info.append(connection_info)

        # 연결 정보를 문자열로 변환
        connection_text = []
        for connection in network_info:
            connection_text.append("Protocol: {}\nLocal Address: {}\nRemote Address: {}\n".format(
                connection["protocol"], connection["local_address"], connection["remote_address"]
            ))

        return "\n".join(connection_text)

    except psutil.NoSuchProcess:
        return "Process with PID {} not found.".format(pid)

# Example usage
pid = 23672  # Replace with the PID of the process you want to monitor
connection_text = get_TCP_IP_connection_by_process(pid)
print("Network Info for PID", pid)
print(connection_text)
