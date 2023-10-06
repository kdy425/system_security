import psutil

def get_network_connection():

    #현재의 tcp, ip 연결 정보를 가져오기
    connection = psutil.net_connections(kind='inet')
    
    for conn in connection:
        print(f"Family : {conn.family}")
        print(f"Type : {conn.type}")
        print(f"Local Address : {conn.laddr}")
        print(f"Remote Address : {conn.raddr}")
        print(f"Status : {conn.status}\n")

if __name__ == "__main__":
    get_network_connection()