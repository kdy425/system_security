import psutil

def get_network_connection():
    connection = psutil.net_connections(kind='inet')
    for conn in connection:
        print(f"Family : {conn.family}")
        print(f"Type : {conn.type}")
        print(f"Local Address : {conn.laddr}")
        print(f"Remote Address : {conn.raddr}")
        print(f"Status : {conn.status}\n")

if __name__ == "__main__":
    get_network_connection()