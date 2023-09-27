import pefile

def print_pe_info(file_path):
    try:
        # PE 파일 열기
        pe = pefile.PE(file_path)

        # DOS 헤더 정보 출력
        print("DOS Header:")
        print("e_magic: 0x{:X}".format(pe.DOS_HEADER.e_magic))
        print("e_lfanew: 0x{:X}".format(pe.DOS_HEADER.e_lfanew))

        # 파일 시그니처 출력
        print("PE Signature: 0x{:X}".format(pe.NT_HEADERS.Signature))

        # 파일 헤더 정보 출력
        print("\nFile Header:")
        print("Machine: 0x{:X}".format(pe.FILE_HEADER.Machine))
        print("Number of Sections: {}".format(pe.FILE_HEADER.NumberOfSections))
        print("Time Date Stamp: 0x{:X}".format(pe.FILE_HEADER.TimeDateStamp))
        print("Characteristics: 0x{:X}".format(pe.FILE_HEADER.Characteristics))

        # 옵셔널 헤더 정보 출력
        print("\nOptional Header:")
        print("Magic: 0x{:X}".format(pe.OPTIONAL_HEADER.Magic))
        print("Address of Entry Point: 0x{:X}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        print("Image Base: 0x{:X}".format(pe.OPTIONAL_HEADER.ImageBase))
        # 추가 필요한 정보들을 출력합니다.

    except Exception as e:
        print("오류 발생:", str(e))

if __name__ == "__main__":
    file_path = "C:\\Users\\ehdbs\\Downloads\\ProcessExplorer\\procexp.exe" #파일경로
    print_pe_info(file_path)
