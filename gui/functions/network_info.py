import psutil
def get_process_name(pid):
    process= psutil.Process(pid)
    process_name = process.name()
    return process_name



def get_ports_by_pid(pid):
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        connections = process.connections()
        
        if not connections:
            return f"No open ports found for PID {pid}"
        
        ports = [conn.laddr.port for conn in connections]
        result = f"Open ports for {process_name}: {', '.join(map(str, ports))}"
        return result
    except psutil.NoSuchProcess as e:
        return f"Error: {e}"



import psutil

def get_TCP_IP_connection_by_process(pid):
    try:
        process = psutil.Process(pid)
        connections = process.connections(kind='inet')

        if not connections:
            return "No network connections found for the process with PID {}.".format(pid)

        protocol_names = {
            1: "icmp",
            2: "igmp",
            4: "ipv4",
            5: "st",
            6: "tcp",
            17: "udp",
            41: "ipv6",
            47: "gre",
            50: "esp",
            51: "ah",
            132: "sctp",
            # Add other protocol numbers and names as needed
            # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml Add from here
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

        # Convert connection information to text
        connection_text = []
        for connection in network_info:
            connection_text.append("Protocol: {}\nLocal Address: {}\nRemote Address: {}\n".format(
                connection["protocol"], connection["local_address"], connection["remote_address"]
            ))

        return "\n".join(connection_text)

    except psutil.NoSuchProcess:
        return "Process with PID {} not found.".format(pid)
    


def get_network_info(pid):
    process_name = get_process_name(pid)
    
    # Get open ports information
    ports_result = get_ports_by_pid(pid)
    
    # Get TCP/IP connection information
    connection_text = get_TCP_IP_connection_by_process(pid)

    # Combine the information into a single string
    network_info_text = f"Network Info for {process_name}\n\n{ports_result}\n\n{connection_text}"

    return network_info_text


'''
# Example usage
pid_to_check = 1234  
result_text = get_network_info(pid_to_check)
print(result_text)
'''
