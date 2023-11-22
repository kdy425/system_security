import psutil
import pefile
import struct
import os

def get_pe_info(pid):
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