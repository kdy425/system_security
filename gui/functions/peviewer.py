import psutil
import pefile

def get_pe_info(pid):
    try:
        # PID를 사용하여 프로세스 정보 가져오기
        process = psutil.Process(pid)

        # 프로세스의 실행 파일 경로 가져오기
        exe_path = process.exe()

        # PE 파일 열기
        pe = pefile.PE(exe_path)

        # PE 정보를 문자열로 저장
        pe_info_str = f"PE Information for PID {pid}:\n"
        pe_info_str += "DOS Header:\n"
        pe_info_str += f"e_magic: 0x{pe.DOS_HEADER.e_magic:X}\n"
        pe_info_str += f"e_lfanew: 0x{pe.DOS_HEADER.e_lfanew:X}\n"

        pe_info_str += "PE Signature: 0x{:X}\n".format(pe.NT_HEADERS.Signature)

        pe_info_str += "File Header:\n"
        pe_info_str += f"Machine: 0x{pe.FILE_HEADER.Machine:X}\n"
        pe_info_str += f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}\n"
        pe_info_str += f"Time Date Stamp: 0x{pe.FILE_HEADER.TimeDateStamp:X}\n"
        pe_info_str += f"Characteristics: 0x{pe.FILE_HEADER.Characteristics:X}\n"

        pe_info_str += "Optional Header:\n"
        pe_info_str += f"Magic: 0x{pe.OPTIONAL_HEADER.Magic:X}\n"
        pe_info_str += f"Address of Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}\n"
        pe_info_str += f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:X}\n"
        # 추가 필요한 정보를 문자열에 추가합니다.

        return pe_info_str  # PE 정보를 문자열로 반환

    except psutil.NoSuchProcess:
        return f"프로세스 {pid}를 찾을 수 없습니다."
    except Exception as e:
        return "오류 발생: " + str(e)