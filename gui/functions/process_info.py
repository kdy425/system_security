#부모프로세스, 자식프로세스 출력
import psutil

def get_process_name(pid):
    process= psutil.Process(pid)
    process_name = process.name()
    return process_name

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


import os
import struct
import psutil

def read_pe_header(pid):
    result = ""  # Initialize an empty string to store the result
    try:
        # Get process information
        process = psutil.Process(pid)
        process_exe = process.exe()

        # Open the process memory
        with open(process_exe, 'rb') as file:
            # Read DOS header
            dos_header = file.read(64)
            e_lfanew_offset = struct.unpack('H', dos_header[60:62])[0]

            # Seek to PE header
            file.seek(e_lfanew_offset)
            pe_signature = file.read(4)

            # Check PE signature
            if pe_signature != b'PE\x00\x00':
                raise ValueError("Not a valid PE file")

            # Read COFF header
            coff_header = file.read(24)
            machine_type = struct.unpack('H', coff_header[0:2])[0]
            characteristics = struct.unpack('H', coff_header[18:20])[0]

            # Read optional header
            optional_header_size = struct.unpack('H', file.read(2))[0]
            file.seek(2, os.SEEK_CUR)  # Skip Magic field
            major_linker_version, minor_linker_version = struct.unpack('BB', file.read(2))
            size_of_code, size_of_initialized_data, size_of_uninitialized_data = struct.unpack('LLL', file.read(12))
            address_of_entry_point, base_of_code, base_of_data = struct.unpack('LLL', file.read(12))

            # Output information
            result += f"Machine Type: {hex(machine_type)}\n"
            result += f"Characteristics: {hex(characteristics)}\n"
            result += f"Optional Header Size: {optional_header_size}\n"
            result += f"Linker Version: {major_linker_version}.{minor_linker_version}\n"
            result += f"Size of Code: {size_of_code}\n"
            result += f"Size of Initialized Data: {size_of_initialized_data}\n"
            result += f"Size of Uninitialized Data: {size_of_uninitialized_data}\n"
            result += f"Entry Point Address: {hex(address_of_entry_point)}\n"
            result += f"Base of Code: {hex(base_of_code)}\n"
            result += f"Base of Data: {hex(base_of_data)}\n"

            # Read section headers
            section_header_size = 40
            num_of_sections = struct.unpack('H', file.read(2))[0]
            result += f"\nNumber of Sections: {num_of_sections}\n"

            for _ in range(num_of_sections):
                section_name = file.read(8).decode('utf-8').rstrip('\0')
                virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data = struct.unpack('LLLL', file.read(section_header_size - 8))
                characteristics = struct.unpack('L', file.read(4))[0]
                
                # Output section information
                result += f"\nSection: {section_name}\n"
                result += f"Virtual Size: {virtual_size}\n"
                result += f"Virtual Address: {hex(virtual_address)}\n"
                result += f"Size of Raw Data: {size_of_raw_data}\n"
                result += f"Pointer to Raw Data: {hex(pointer_to_raw_data)}\n"
                result += f"Characteristics: {hex(characteristics)}\n"

    except Exception as e:
        result += f"Error: {e}\n"

    return result

# Example usage
#pid = 24276  # Replace with the desired PID



'''if __name__ == "__main__":
    read_pe_header(pid)'''

def get_process_info(pid):
    process_name = get_process_name(pid)
    get_pp_info = get_process_parent_child(pid)
    get_pe = read_pe_header(pid)

    # Combine the information into a single string
    process_info_text = f"process Info for {process_name}\n\n{get_pp_info}\n\nPE header for {process_name}\n{get_pe}"

    return process_info_text


#result_text = get_process_info(pid)
#print(result_text)