#!/usr/bin/env python3
import sys
from datetime import datetime
import binascii



# from macho_parser.macho_parser import MachO
def get_hex(bytes):
    bytes = bytearray.fromhex(bytes[0:4]+bytes[4:8])
    bytes.reverse()
    return bytes.hex()

def get_rwa(addr, import_addr_table, raw_addr):
    raw_name_table = int(addr, 16) - import_addr_table + raw_addr
    if raw_name_table < 922337203685477172:
        return raw_name_table
    else:
        return 0


def read4hex(bytes):
    # cffaedfe
    # feedfacf
    if len(bytes)%2!=0:
        bytes +='0'
    ba = bytearray.fromhex(bytes)
    ba.reverse()
    return ba.hex()



def read4str(bytes):
    # cffaedfe
    # feedfacf
    try:
        ba = bytearray.fromhex(bytes)
    except:
        return " "
    return ba.hex()


def parse_command(segment):
    print("LC_segment", int(read4hex(segment[0:8]), 16))
    section_size = int(read4hex(segment[8:16]), 16)
    print("size of section structure ", int(read4hex(segment[8:16]), 16))
    name = read4str(segment[16:48])
    try:
        print("Name of Segment structure ", bytes.fromhex(name).decode("utf-8"))
    except:
        pass
    print("vmaddr", int(read4hex(segment[48:64]), 16))
    print("seg memory size ", int(read4hex(segment[64:80]), 16))
    print("file offset ", int(read4hex(segment[80:96]), 16))
    print("filesize ", int(read4hex(segment[96:112]), 16))
    print("maxprot ", int(read4hex(segment[112:120]), 16))
    print("initprot ", int(read4hex(segment[120:128]), 16))
    print("number of section ", int(read4hex(segment[128:136]), 16))
    sec_number = int(read4hex(segment[128:136]), 16)
    print("flags ", int(read4hex(segment[136:144]), 16))
    if sec_number > 0:
        print("\nsections\n")
        sec_start = 144
        for i in range(sec_number):
            name = read4str(segment[sec_start:sec_start + 32])
            # print("raw name = ",name)
            try:
                print("section name ", bytes.fromhex(name).decode("utf-8"))
            except:
                pass
            sec_start += 32
            name = read4str(segment[sec_start:sec_start + 32])
            # print("raw name = ",name)
            try:
                print("segment section name ", bytes.fromhex(name).decode("utf-8"))
            except:
                pass
            sec_start += 32
            print("vmaddr", int(read4hex(segment[sec_start:sec_start + 16]), 16), segment[sec_start:sec_start + 16])
            sec_start += 16
            print("seg memory size ", int(read4hex(segment[sec_start:sec_start + 16]), 16))
            sec_start += 16
            print("file offset ", int(read4hex(segment[sec_start:sec_start + 8]), 16))
            sec_start += 8
            print("align", int(read4hex(segment[sec_start:sec_start + 8]), 16))
            sec_start += 8
            print("reloff", int(read4hex(segment[sec_start:sec_start + 8]), 16))
            sec_start += 8
            print("nreloc", int(read4hex(segment[sec_start:sec_start + 8]), 16))
            sec_start += 8
            print("flags", int(read4hex(segment[sec_start:sec_start + 8]), 16))
            sec_start += 32

    print("\n\n")

    return section_size


try:
    file = sys.argv[1]
except IndexError:
    print("add file name in first arg")
# with MachO(file) as m:
#    print (m.get_header())

with open(file, "rb") as f:
    ba = f.read().hex()

# print(ba[0:100])
#print("magic = ", read4hex(ba[0:8]))
if "5a4d" in read4hex(ba[0:8]):
    raw_import_section = 0
    virtual_address_import = 0
    print("PE Magic", read4hex(ba[0:4]))
    print("e_cblp", read4hex(ba[4:8]))
    print("e_cp", read4hex(ba[8:12]))
    print("e_crlc", read4hex(ba[12:16]))
    print("e_cparhdr", read4hex(ba[16:20]))
    print("e_minalloc", read4hex(ba[20:24]))
    print("e_maxalloc", read4hex(ba[24:28]))
    print("e_ss", read4hex(ba[28:32]))
    print("s_sp", read4hex(ba[32:36]))
    print("e_csum", read4hex(ba[36:40]))
    print("e_ip", read4hex(ba[40:44]))
    print("e_cs", read4hex(ba[44:48]))
    print("e_lfarlc", read4hex(ba[48:52]))
    print("e_ovno", read4hex(ba[52:56]))
    print("e_res", read4hex(ba[56:72]))
    print("s_oemid", read4hex(ba[72:76]))
    print("e_oeminfo", read4hex(ba[76:80]))
    print("e_res2", read4hex(ba[80:120]))
    e_lfanew = int(read4hex(ba[120:128]), 16)
    print("e_lfanew", read4hex(ba[120:128]))
    new_offset = e_lfanew * 2 + 8
    print(new_offset)
    print("Machine", read4hex(ba[new_offset:new_offset + 4]))
    new_offset += 4
    print("Number of section", int(read4hex(ba[new_offset:new_offset + 4]), 16))
    sec_num = int(read4hex(ba[new_offset:new_offset + 4]), 16)
    new_offset += 4
    print("Time Date Stamp", int(read4hex(ba[new_offset:new_offset + 8]), 16), " ",
          read4hex(ba[new_offset:new_offset + 8]))
    dt_object = int(read4hex(ba[new_offset:new_offset + 8]), 16)
    dt_object = datetime.fromtimestamp(dt_object)
    print("dt_object =", dt_object)
    new_offset += 24
    size_of_optional_header = int(read4hex(ba[new_offset:new_offset + 4]), 16)
    print("SIZE of opt header = ", size_of_optional_header)
    new_offset += 4
    print("Characterisitcs ", read4hex(ba[new_offset:new_offset + 4]))
    new_offset += 4
    #print("old offset = ", hex(new_offset // 2))
    new_offset = new_offset + size_of_optional_header*2-32*8

    #print("NEW_OFFSET = ", hex(new_offset // 2))

    # addr_of_entry_point=int(read4hex(ba[352:360]),16)
    # print("Addr of entry point", addr_of_entry_point)
    print("export dir RVA = ", read4hex(ba[new_offset:new_offset + 8]))
    export_rva = int(read4hex(ba[new_offset:new_offset + 8]), 16)
    new_offset += 8
    print("export dir size = ", read4hex(ba[new_offset:new_offset + 8]))
    export_size = int(read4hex(ba[new_offset:new_offset + 8]), 16)
    new_offset += 8
    print("import dir RVA = ", read4hex(ba[new_offset:new_offset + 8]))
    import_rva = int(read4hex(ba[new_offset:new_offset + 8]), 16)
    new_offset += 8
    print("import dir size = ", read4hex(ba[new_offset:new_offset + 8]))
    import_size = int(read4hex(ba[new_offset:new_offset + 8]), 16)
    new_offset += 168

    import_addr_table = int(read4hex(ba[new_offset:new_offset + 8]), 16)
    print("import address table = ", read4hex(ba[new_offset:new_offset + 8]), import_addr_table)
    new_offset += 8
    print("size address table = ", read4hex(ba[new_offset:new_offset + 8]))
    size_addr_table = int(read4hex(ba[new_offset:new_offset + 8]), 16) * 2
    new_offset += 56
    print("Sec_num",sec_num)
    raw_export_Table = 0
    for i in range(sec_num):
        # print(ba[new_offset:new_offset+16])
        print("\n")
        name = read4str(ba[new_offset:new_offset + 16])
        print("section name .",  bytes.fromhex(name).decode("utf-8").strip())
        new_offset += 16
        print("virt size ", read4hex(ba[new_offset:new_offset + 8]))
        new_offset += 8

        virt_addr = int(read4hex(ba[new_offset:new_offset + 8]), 16)
        print("virt addr ", read4hex(ba[new_offset:new_offset + 8]), virt_addr)

        new_offset += 8
        print("raw size ", read4hex(ba[new_offset:new_offset + 8]))
        raw_size = int(read4hex(ba[new_offset:new_offset + 8]), 16)
        new_offset += 8
        print("raw addr ", read4hex(ba[new_offset:new_offset + 8]))

        print(hex(import_rva), hex(virt_addr))
        raw_addr = int(read4hex(ba[new_offset:new_offset + 8]), 16)
        temp = import_rva - virt_addr + raw_addr
        border = raw_addr + raw_size
        temp_export = export_rva - virt_addr + raw_addr
        #print("Temp_export = ", hex(temp_export))
        #print("TEMP = ", hex(temp),hex(border))
        if temp >= raw_addr and temp <= border:
            #print("Found raw import section")
            raw_import_section = raw_addr
            virtual_address_import = virt_addr
            raw_import_table = hex(import_rva - virt_addr + raw_import_section)
        if temp_export >= raw_addr and temp <= border:
            #print("Found raw export section")
            raw_export_section = raw_addr
            virt_addr_export = virt_addr
            raw_export_Table = temp_export


        new_offset += 8
        print("relloc addr ", read4hex(ba[new_offset:new_offset + 8]))
        new_offset += 8
        print("linenumbers ", read4hex(ba[new_offset:new_offset + 8]))
        new_offset += 8
        print("reloc numbers ", read4hex(ba[new_offset:new_offset + 4]))
        new_offset += 4
        print("linenumbers number ", read4hex(ba[new_offset:new_offset + 4]))
        new_offset += 4
        print("characteristic ", read4hex(ba[new_offset:new_offset + 8]))
        new_offset += 8
    #print("RAW EXPORT TABLE = ",hex(raw_export_Table))
    raw_export_Table*=2
    if (raw_export_Table != 0):
        print("\n\nExports\n")

        export_section = ba[raw_export_Table:raw_export_Table+80]

        dll_name_rva = read4hex(export_section[24:32])
        numberOfFunction = int(read4hex(export_section[40:48]),16)
        numberOfNames = export_section[48:56]
        AddressOfFunction=read4hex(export_section[56:64])
        AddressOfNames=read4hex(export_section[64:72])
        rwa_address = get_rwa(AddressOfNames, virt_addr_export, raw_export_section)
        #print("RWA ADDRESS = ",hex(rwa_address))
        rwa_address*=2
        #print("Export dll name = ", hex(name))
        adresses = []
        for i in range(numberOfFunction):
            temp_addr = get_rwa(read4hex(ba[rwa_address:rwa_address+8]),virt_addr_export,raw_export_section)
            #print("addr of func = ",hex(temp_addr))
            adresses.append(temp_addr)
            rwa_address+=8
        for i in adresses:
            tmp = i*2
            off = ba.find("00",tmp)
            name = read4str(ba[tmp:off])

            print("Export Function = ", bytes.fromhex(name).decode("utf-8").strip())

    #print("RAW_IMPORT_TABLE = ", raw_import_table)
    raw_import_table = int(raw_import_table, 16) * 2
    #print(raw_import_table)
    i = 0
    print("\n\nIMPORTS\n")
    imports = []
    while True:
        img_import_descr = ba[raw_import_table:raw_import_table + 40]
        if img_import_descr == '0' * 40:
            break
        #print(img_import_descr)
        raw_name_table = read4hex(img_import_descr[0:8])
        #print("OFT = ", raw_name_table)
        raw_name_table = hex(int(raw_name_table, 16) - virtual_address_import + raw_import_section)
        imports.append(int(raw_name_table, 16))
        #print("raw function table = ", raw_name_table)
        off = ba.find("0" * 24, int(raw_name_table, 16) * 2)
        func = ba[int(raw_name_table, 16) * 2:off]
        #print("FUNC = ", func)
        func = [func[i:i + 16] for i in range(0, len(func), 16)]
        #print(func)
        func = [read4hex(ad) for ad in func]
        #print(func)
        func = [get_rwa(ad, virtual_address_import, raw_import_section) for ad in func if
                get_rwa(ad, virtual_address_import, raw_import_section) != 0]
        #print("\nafter")
        for ad in func:
            #print(hex(ad))
            off = ba.find("00", int(ad) * 2 + 4)
            func_name = ba[ad * 2 + 4:off]
            name = read4str(func_name)
            try:
                name = bytes.fromhex(name).decode("utf-8").strip()
                if (len(name) > 1 ):
                    print("function", name)
            except:
                pass
        raw_name = read4hex(img_import_descr[24:32])
        #print("RAV DLL NAME = ",raw_name)
        raw_name = hex(int(raw_name, 16) - virtual_address_import + raw_import_section)
        #print("test = ", hex(virtual_address_import//2),hex(raw_import_section//2))
        #print("RAW DLL NAME = ", raw_name)
        #print("RVA_name = ", raw_name)
        #print(raw_name)
        raw_name = int(raw_name, 16) * 2
        off = ba.find("00", raw_name)
        name = read4str(ba[raw_name:off])
        try:
            print("DLL ", bytes.fromhex(name).decode("utf-8").strip())
        except:
            pass

        FT = read4hex(img_import_descr[32:40])
        #print("FT (IAT) = ", FT)
        FT = hex(int(FT, 16) - virtual_address_import + raw_import_section)
        #print("FT (IAT) = ", FT)
        raw_import_table += 40
        i += 1




elif "feedfacf" in read4hex(ba[0:8]):
    print("Mach-o")
    print("cpu_type = ", read4hex(ba[8:16]))
    print("cpu_subtype = ", read4hex(ba[16:24]))
    print("file_type = ", read4hex(ba[24:32]))
    if (int(read4hex(ba[24:32]),16) == 2):
        print("demand paged executable file")
    print("number of commands = ", int(read4hex(ba[32:40]), 16))
    ncmnds = int(read4hex(ba[32:40]), 16)
    print("sizeof commands = ", int(read4hex(ba[40:48]), 16))
    print("flags = ", read4hex(ba[48:56]))

    # with MachO(file) as m:
    #    for sect in m.get_load_commands():
    #        print(sect)
    offset = 64
    for i in range(ncmnds - 1):
        cmd = int(read4hex(ba[offset:offset + 8]), 16)
        # print(cmd)
        cmdsize = int(read4hex(ba[offset + 8:offset + 16]), 16)
        # print("cmdsize = ", cmdsize)
        if cmd == 25:
            segment = ba[offset:offset + cmdsize * 2]
            sec_size = parse_command(segment)
            # print("sec_size = ", sec_size)
        offset += cmdsize * 2

    # with MachO(file) as m:
    #    for sect in m.get_segments():
    #        print(sect)
    # print("\nsections\n")
    # with MachO(file) as m:
    #    for sect in m.get_sections():
    #        print(sect)

else:
    

    print("Headers\n")

    with open(sys.argv[1],'rb') as f:
        bytes=f.read().hex()
        #print(bytes)
    #print(bytes[0:14])
    e_ident = bytes[0:32]
    if bytes[0:8] == "7f454c46":
        print("ELF")
    #print(bytes)
    if (bytes[8:10] == '02'):
        print('64 bit')
    else:
        print('32 bit')
    #print(bytes)
    if (bytes[10:12] == '01'):
        print('little end')
    elif(bytes[10:12] == '02'):
        print('big -end')
    #print('OS-ABI',bytes)
    if (bytes[14:16] == '00'):
        print('System V')
    else:
        print("other")
    file_type = read4hex(bytes[32:36])
    print("file_type = ", file_type)

    e_entry = read4hex(bytes[48:64])
    print("entry point address=",e_entry, int(e_entry,16))

    e_phoff = read4hex(bytes[64:80])
    print("  Start of program headers",e_phoff, int(e_phoff,16))


    e_shoff = read4hex(bytes[80:96])
    print("Start of section headers",e_shoff,int(e_shoff,16))
    section_size = int(read4hex(bytes[120:124]),16)
    string_table = int(read4hex(bytes[124:128]),16)
    print("String_table", string_table)
    e_shoff = int(e_shoff,16)*2
    print("\nInputs\n", section_size)
    shstrtab_addr = e_shoff + string_table*128
    print("ADDR = ", hex(shstrtab_addr//2))
    string_table_addr = int(read4hex(bytes[shstrtab_addr+48:shstrtab_addr+64]),16)
    string_table_size = int(read4hex(bytes[shstrtab_addr+64:shstrtab_addr+80]),16)
    #print(hex(string_table_addr), hex(string_table_size))
    string_table_addr*=2
    strings = bytes[string_table_addr+2:string_table_addr+string_table_size*2]
    #print(strings)
    strings_list = strings.split("00")
    strings_list.pop()
    #strings = [i+"0" for i in strings if len(i)%2!=0]
    #print(strings)
    #for i in range(len(strings)):
    #    try:
    #        print(i ,bytearray.fromhex(strings[i]).decode())
    #    except:
    #        strings[i]+="0"
    #        strings[i+1]=strings[i+1][1:]
    #        print(i, bytearray.fromhex(strings[i]).decode())

    #for i in range (section_size):
    #    
    #    #print("-------------------")
    #    sh_ind = int(read4hex(section[0:8]),16)
    #    print(sh_ind)
    #    off = strings.find("00", sh_ind)
    #    print(strings[sh_ind:off])#,bytearray.fromhex(strings[sh_ind:off]).decode())
    #    sh_type = read4hex(section[8:16])
    #    sh_type = int(sh_type,16)
    #    sh_flag = read4hex(section[16:32])
    #    sh_flag = int(sh_flag,16)
    #print(sh_type, sh_flag)
    for i in range (section_size-1):
        section = bytes[e_shoff:e_shoff+128]
        #print(hex(e_shoff//2),i)# , section)
        sh_flag = int(read4hex(section[8:16]),16)
        #print(sh_flag)
        #print(sh_flag)
        if (sh_flag == 3):
            fun_addr = read4hex(section[48:64])
            fun_size = read4hex(section[64:80])
            #print("FUNC_Addr = ",fun_addr,fun_size)
            dec_fun_addr = int(fun_addr,16)*2
            dec_fun_size = int(fun_size,16)*2
            #print("dec fun addr", dec_fun_addr,dec_fun_size)
            functions = bytes[dec_fun_addr+4:dec_fun_addr+dec_fun_size]
            #print(functions)
            functions = functions.split("00")
            for i in functions:
                #print(i)
                try:
                    print(bytearray.fromhex(i).decode())
                except:
                    pass

        e_shoff+=128

