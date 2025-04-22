#!/usr/bin/env python3

import datetime
import glob
import os
import pefile
import stat
import struct
import sys
import unicorn as uc
import unicorn.x86_const as ux

# overall memory map:
# 0x00400000        PE
# 0x7C000000        end of stack
# 0x7C000000        import glue
# 0x7C010000        TEB
# 0x7C020000        GDT(?!)
# 0x7C030000        environment and args

PAGE_SZ = 64*1024

STACK_SIZE = 32*1024*1024
STACK_END = 0x7C000000

SYSCALL_EMU_ADDR = STACK_END
SYSCALL_EMU_SZ = PAGE_SZ

TEB_ADDR = SYSCALL_EMU_ADDR + PAGE_SZ
GDT_ADDR = TEB_ADDR + PAGE_SZ
ENV_ARGS_ADDR = GDT_ADDR + PAGE_SZ

FORCE_NO_JIT = True
TRACE = False

# load the PE
pe = pefile.PE('BC5/BIN/TLINK32.EXE')

img_base = pe.OPTIONAL_HEADER.ImageBase
img_sz = pe.OPTIONAL_HEADER.SizeOfImage
print(f"Total 0x{img_sz:08x} bytes @ 0x{img_base:08x}")

HEAP_START = (img_base + img_sz + PAGE_SZ - 1) // PAGE_SZ * PAGE_SZ
print(f"Free memory starting at 0x{HEAP_START:08x}")

emu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
emu.mem_map(img_base, img_sz, uc.UC_PROT_READ)

# set up env, args
env_args = b''
env_ptr = ENV_ARGS_ADDR
# env vars (TODO)
env_args += b'\x00'
args_ptr = ENV_ARGS_ADDR + len(env_args)
# command line (TODO)
env_args += "bcc32".encode()
for arg in sys.argv[1:]:
    env_args += (" " + arg).encode()
env_args += b'\x00'
assert len(env_args) <= PAGE_SZ
emu.mem_map(ENV_ARGS_ADDR, PAGE_SZ, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
emu.mem_write(ENV_ARGS_ADDR, env_args)
print(f"Args block: {env_args}")

# syscall emu
last_error = 0
ERROR_FILE_NOT_FOUND = 2
ERROR_INVALID_HANDLE = 6
ERROR_NO_MORE_FILES = 18
ERROR_NOT_SUPPORTED = 50
ERROR_INVALID_PARAMETER = 87
ERROR_MOD_NOT_FOUND = 126
ERROR_PROC_NOT_FOUND = 127
ERROR_INVALID_ADDRESS = 487

hfile_table = [
    sys.stdin.buffer,
    sys.stdout.buffer,
    sys.stderr.buffer,
]
hfind_table = []

def get_stack_arg(emu, n):
    esp = emu.reg_read(ux.UC_X86_REG_ESP)
    return struct.unpack("<I", emu.mem_read(esp + (n+1) * 4, 4))[0]

def get_c_str(emu, addr):
    ret = b''
    while True:
        c = emu.mem_read(addr, 1)
        if c == b'\x00':
            return ret
        ret += c
        addr += 1

def GetModuleHandleA(emu):
    global last_error
    module_name = get_stack_arg(emu, 0)
    if module_name == 0:
        ret = img_base
    else:
        module_name = get_c_str(emu, module_name)
        print(f"GetModuleHandleA {module_name.decode('ascii', errors='replace')}")
        last_error = ERROR_MOD_NOT_FOUND
        ret = 0
    return ret

def GetProcAddress(emu):
    global last_error
    module = get_stack_arg(emu, 0)
    p_name = get_stack_arg(emu, 1)
    name = get_c_str(emu, p_name)
    print(f"GetProcAddress 0x{module:08x}!{name.decode('ascii', errors='replace')} (DUMMY)")
    last_error = ERROR_PROC_NOT_FOUND
    return 0

def GetEnvironmentStrings(emu):
    return env_ptr

def GetCommandLineA(emu):
    return args_ptr

def GetVersion(emu):
    return 0x0105   # winxp (5.1)

def GetModuleFileNameA(emu):
    global last_error
    module = get_stack_arg(emu, 0)
    out_fn = get_stack_arg(emu, 1)
    out_sz = get_stack_arg(emu, 2)
    if module == 0:
        # todo
        filename = b"C:\\BC5\\BIN\\BCC32.EXE\x00"
        sz = min(out_sz, len(filename))
        print(f"GetModuleFileNameA write to 0x{out_fn:08x} sz 0x{sz:x} orig_sz 0x{out_sz:x}")
        emu.mem_write(out_fn, filename[:sz])
        return len(filename) - 1
    last_error = ERROR_MOD_NOT_FOUND
    return 0

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
def VirtualAlloc(emu):
    global HEAP_START
    global last_error
    addr = get_stack_arg(emu, 0)
    sz = get_stack_arg(emu, 1)
    ty = get_stack_arg(emu, 2)
    prot = get_stack_arg(emu, 3)

    if (ty & MEM_COMMIT) and not (ty & MEM_RESERVE) and addr:
        print(f"VirtualAlloc @ 0x{addr:08x} sz 0x{sz:08x} type 0x{ty:08x} prot 0x{prot:08x} (COMMIT)")
        return addr

    if addr:
        last_error = ERROR_INVALID_ADDRESS
        return 0

    print(f"VirtualAlloc @ 0x{addr:08x} sz 0x{sz:08x} type 0x{ty:08x} prot 0x{prot:08x}")

    addr = HEAP_START
    if sz == 0:
        sz = 1
    real_sz = (sz + PAGE_SZ - 1) // PAGE_SZ * PAGE_SZ
    HEAP_START += real_sz

    # XXX we ignore type and prot, and just give it read/write
    emu.mem_map(addr, real_sz, uc.UC_PROT_READ | uc.UC_PROT_WRITE)

    return addr

def VirtualFree(emu):
    addr = get_stack_arg(emu, 0)
    sz = get_stack_arg(emu, 1)
    ty = get_stack_arg(emu, 2)
    print(f"VirtualFree @ 0x{addr:08x} sz 0x{sz:08x} type 0x{ty:08x} (DUMMY)")
    return 1

def GetStdHandle(emu):
    global last_error
    std_handle = get_stack_arg(emu, 0)
    print(f"GetStdHandle {std_handle:08x}")
    if std_handle == 0xfffffff6:
        # stdin
        return 0 << 2
    if std_handle == 0xfffffff5:
        # stdout
        return 1 << 2
    if std_handle == 0xfffffff4:
        # stderr
        return 2 << 2
    last_error = ERROR_INVALID_HANDLE
    return 0xffffffff

def ReadFile(emu):
    global last_error
    hfile = get_stack_arg(emu, 0)
    buffer = get_stack_arg(emu, 1)
    sz = get_stack_arg(emu, 2)
    read = get_stack_arg(emu, 3)
    overlapped = get_stack_arg(emu, 4)

    if overlapped:
        last_error = ERROR_NOT_SUPPORTED
        return 0

    if hfile >> 2 >= len(hfile_table):
        last_error = ERROR_INVALID_HANDLE
        return 0

    ioio = hfile_table[hfile >> 2]
    buf = ioio.read(sz)

    emu.mem_write(buffer, buf)

    if read:
        emu.mem_write(read, struct.pack("<I", len(buf)))
    return 1

def WriteFile(emu):
    global last_error
    hfile = get_stack_arg(emu, 0)
    buffer = get_stack_arg(emu, 1)
    sz = get_stack_arg(emu, 2)
    written = get_stack_arg(emu, 3)
    overlapped = get_stack_arg(emu, 4)

    buf = emu.mem_read(buffer, sz)

    if overlapped:
        last_error = ERROR_NOT_SUPPORTED
        return 0

    if hfile >> 2 >= len(hfile_table):
        last_error = ERROR_INVALID_HANDLE
        return 0

    ioio = hfile_table[hfile >> 2]
    ioio.write(buf)

    if written:
        emu.mem_write(written, struct.pack("<I", sz))
    return 1

def SetFilePointer(emu):
    global last_error
    hfile = get_stack_arg(emu, 0)
    dist_lo = get_stack_arg(emu, 1)
    pdist_hi = get_stack_arg(emu, 2)
    method = get_stack_arg(emu, 3)

    if hfile >> 2 >= len(hfile_table):
        last_error = ERROR_INVALID_HANDLE
        return 0
    
    ioio = hfile_table[hfile >> 2]

    if pdist_hi:
        dist_hi = struct.unpack("<I", emu.mem_read(pdist_hi, 4))[0]
        dist_ = (dist_hi << 32) | dist_lo
        if dist_ & 0x80000000_00000000:
            dist = dist_ = 0x1_00000000_00000000
        else:
            dist = dist_
    else:
        if dist_lo & 0x80000000:
            dist = dist_lo - 0x1_0000_0000
        else:
            dist = dist_lo
    
    print(f"SetFilePointer {ioio} disp {dist} method {method}")
    ioio.seek(dist, method)
    pos = ioio.tell()

    if pdist_hi:
        emu.mem_write(pdist_hi, struct.pack("<I", pos >> 32))
    return pos & 0xffffffff

def CloseHandle(emu):
    global last_error
    hfile = get_stack_arg(emu, 0)

    if hfile >> 2 >= len(hfile_table):
        last_error = ERROR_INVALID_HANDLE
        return 0

    if hfile >> 2 >= 2:
        hfile_table[hfile >> 2].close()
    return 1

def ExitProcess(emu):
    code = get_stack_arg(emu, 0)
    print(f"Process executed with status: {code}")
    emu.mem_write(emu.reg_read(ux.UC_X86_REG_ESP), b'\xff\xff\xff\xff')
    return 0

def SetHandleCount(emu):
    return get_stack_arg(emu, 0)

def GetStartupInfoA(emu):
    info = get_stack_arg(emu, 0)
    emu.mem_write(info, struct.pack("<IIIIIIIIIIIIHHIIII", 17*4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    return 0

def GetFileType(emu):
    hfile = get_stack_arg(emu, 0)

    if hfile >> 2 >= len(hfile_table):
        last_error = ERROR_INVALID_HANDLE
        return 0
    
    ioio = hfile_table[hfile >> 2]

    if ioio.isatty():
        return 2
    if not ioio.seekable():
        return 3
    return 1

def SetConsoleCtrlHandler(emu):
    fn = get_stack_arg(emu, 0)
    add = get_stack_arg(emu, 1)
    print(f"SetConsoleCtrlHandler {"add" if add else "del"} @ 0x{fn:08x} (DUMMY)")
    return 1

def GetLocalTime(emu):
    dt = datetime.datetime.now()
    info = get_stack_arg(emu, 0)
    emu.mem_write(info, struct.pack("<HHHHHHHH", dt.year, dt.month, (dt.weekday() + 1) % 7, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond // 1000))
    return 0

def GetSystemInfo(emu):
    dt = datetime.datetime.now()
    info = get_stack_arg(emu, 0)
    emu.mem_write(info, struct.pack("<HHIIIIIIIHH", 0, 0, PAGE_SZ, 0, 0xffffffff, 1, 1, 586, PAGE_SZ, 6, 0))
    return 0

def GetLastError(emu):
    return last_error

MAX_PATH = 260
def fn_to_find_data(fn):
    s = os.stat(fn)

    if stat.S_ISDIR(s.st_mode):
        ret = struct.pack("<I", 0x10)
    else:
        ret = struct.pack("<I", 0x80)

    # XXX skip timestamps
    ret += b'\x00\x00\x00\x00\x00\x00\x00\x00' * 3
    ret += struct.pack("<IIII", s.st_size >> 32, s.st_size & 0xffffffff, 0, 0)
    ret += fn + b'\x00'
    return ret

def FindFirstFileA(emu):
    global last_error
    p_fn = get_stack_arg(emu, 0)
    fn = get_c_str(emu, p_fn)
    out = get_stack_arg(emu, 1)
    print(f"FindFirstFileA {fn}")

    files = glob.glob(fn)
    if len(files) == 0:
        last_error = ERROR_FILE_NOT_FOUND
        return 0xffffffff

    find_data = fn_to_find_data(files[0])
    emu.mem_write(out, find_data)

    hfind = len(hfind_table) << 2
    hfind_table.append(files[1:])
    return hfind

def FindNextFileA(emu):
    global last_error
    hfind = get_stack_arg(emu, 0) >> 2
    out = get_stack_arg(emu, 1)

    if hfind >= len(hfind_table):
        last_error = ERROR_INVALID_HANDLE
        return 0

    files = hfind_table[hfind >> 2]
    print(f"FindNextFileA {files}")

    if len(files) == 0:
        last_error = ERROR_NO_MORE_FILES
        return 0

    find_data = fn_to_find_data(files[0])
    emu.mem_write(out, find_data)
    hfind_table[hfind >> 2] = files[1:]
    return 1

def FindClose(emu):
    global last_error
    hfind = get_stack_arg(emu, 0) >> 2

    if hfind >= len(hfind_table):
        last_error = ERROR_INVALID_HANDLE
        return 0

    hfind_table[hfind >> 2] = []
    return 1

def GetFileAttributesA(emu):
    global last_error
    p_fn = get_stack_arg(emu, 0)
    fn = get_c_str(emu, p_fn)
    print(f"GetFileAttributesA {fn}")

    # HACK
    if fn.startswith(b'Z:\\'):
        return 0x80

    try:
        s = os.stat(fn)
        if stat.S_ISDIR(s.st_mode):
            return 0x10
        else:
            return 0x80
    except FileNotFoundError:
        last_error = ERROR_FILE_NOT_FOUND
    last_error = ERROR_NOT_SUPPORTED
    return 0xffffffff


def CreateFileA(emu):
    global last_error
    p_fn = get_stack_arg(emu, 0)
    fn = get_c_str(emu, p_fn)
    dwDesiredAccess = get_stack_arg(emu, 1)
    dwShareMode = get_stack_arg(emu, 2)
    lpSecurityAttributes = get_stack_arg(emu, 3)
    dwCreationDisposition = get_stack_arg(emu, 4)
    dwFlagsAndAttributes = get_stack_arg(emu, 5)
    hTemplateFile = get_stack_arg(emu, 6)
    print(f"CreateFileA {fn} {dwCreationDisposition}")

    # not very accurate emulation lol
    if dwCreationDisposition == 1 or dwCreationDisposition == 2 or dwCreationDisposition == 5:
        mode = 'w+b'
    elif dwCreationDisposition == 3 or dwCreationDisposition == 4:
        mode = 'r+b'
    else:
        last_error = ERROR_INVALID_PARAMETER
        return 0xffffffff
    
    try:
        ioio = open(fn, mode)
    except FileNotFoundError:
        last_error = ERROR_FILE_NOT_FOUND
        return 0xffffffff
    
    hfile = len(hfile_table) << 2
    hfile_table.append(ioio)
    return hfile

def DeleteFileA(emu):
    global last_error
    p_fn = get_stack_arg(emu, 0)
    fn = get_c_str(emu, p_fn)
    print(f"DeleteFileA {fn}")

    # pretend to delete the file
    return 1

    # try:
    #     os.unlink(fn)
    #     return 1
    # except FileNotFoundError:
    #     last_error = ERROR_FILE_NOT_FOUND
    # last_error = ERROR_NOT_SUPPORTED
    # return 0

def GetVolumeInformationA(emu):
    lpRootPathName = get_stack_arg(emu, 0)
    lpVolumeNameBuffer = get_stack_arg(emu, 1)
    nVolumeNameSize = get_stack_arg(emu, 2)
    lpVolumeSerialNumber = get_stack_arg(emu, 3)
    lpMaximumComponentLength = get_stack_arg(emu, 4)
    lpFileSystemFlags = get_stack_arg(emu, 5)
    lpFileSystemNameBuffer = get_stack_arg(emu, 6)
    nFileSystemNameSize = get_stack_arg(emu, 7)

    if lpRootPathName:
        lpRootPathName = get_c_str(emu, lpRootPathName)
        print(f"GetVolumeInformationA {lpRootPathName} (UNIMPL!)")
        return 0

    if lpVolumeNameBuffer:
        volname = b"Emulation\x00"
        sz = min(nVolumeNameSize, len(volname))
        print(f"GetVolumeInformationA retrieving name")
        emu.mem_write(lpVolumeNameBuffer, volname[:sz])
    if lpVolumeSerialNumber:
        print(f"GetVolumeInformationA retrieving serial")
        emu.mem_write(lpVolumeSerialNumber, b'\xde\xad\xbe\xef')
    if lpMaximumComponentLength:
        print(f"GetVolumeInformationA retrieving max path component")
        emu.mem_write(lpMaximumComponentLength, struct.pack("<I", 255))
    if lpFileSystemFlags:
        print(f"GetVolumeInformationA retrieving flags")
        emu.mem_write(lpFileSystemFlags, struct.pack("<I", 0x6))
    if lpFileSystemNameBuffer:
        fsname = b"EMU\x00"
        sz = min(nFileSystemNameSize, len(fsname))
        print(f"GetVolumeInformationA retrieving fs")
        emu.mem_write(lpFileSystemNameBuffer, fsname[:sz])

    return 1

def FileTimeToLocalFileTime(emu):
    inp = get_stack_arg(emu, 0)
    outp = get_stack_arg(emu, 1)
    emu.mem_write(outp, b'\x00\x00\x00\x00\x00\x00\x00\x00')
    return 1

def FileTimeToDosDateTime(emu):
    inp = get_stack_arg(emu, 0)
    outp_date = get_stack_arg(emu, 1)
    outp_time = get_stack_arg(emu, 1)
    emu.mem_write(outp_date, b'\x00\x00\x00\x00')
    emu.mem_write(outp_time, b'\x00\x00\x00\x00')
    return 1

def GetCurrentDirectoryA(emu):
    sz = get_stack_arg(emu, 0)
    buf = get_stack_arg(emu, 1)

    fake_cur_dir = b"Z:\\\x00"
    sz = min(sz, len(fake_cur_dir))
    emu.mem_write(buf, fake_cur_dir[:sz])
    return len(fake_cur_dir)

def GetFullPathNameA(emu):
    inp = get_stack_arg(emu, 0)
    inp = get_c_str(emu, inp)
    bufsz = get_stack_arg(emu, 1)
    buf = get_stack_arg(emu, 2)
    p_fn = get_stack_arg(emu, 3)
    print(f"GetFullPathNameA {inp} (UNIMPL!)")
    return 0

def CreateProcessA(emu):
    lpApplicationName = get_stack_arg(emu, 0)
    if lpApplicationName:
        app_name = get_c_str(emu, lpApplicationName)
    else:
        app_name = ""
    lpCommandLine = get_stack_arg(emu, 1)
    if lpCommandLine:
        cmdline = get_c_str(emu, lpCommandLine)
    else:
        cmdline = ""
    lpProcessAttributes = get_stack_arg(emu, 2)
    lpThreadAttributes = get_stack_arg(emu, 3)
    bInheritHandles = get_stack_arg(emu, 4)
    dwCreationFlags = get_stack_arg(emu, 5)
    lpEnvironment = get_stack_arg(emu, 6)
    lpCurrentDirectory = get_stack_arg(emu, 7)
    lpStartupInfo = get_stack_arg(emu, 8)
    lpProcessInformation = get_stack_arg(emu, 9)
    print(f"CreateProcessA {app_name} {cmdline} (UNIMPL!)")
    return 0

def GetTimeZoneInformation(emu):
    return 0xffffffff

def GetPrivateProfileStringA(emu):
    global last_error
    lpAppName = get_stack_arg(emu, 0)
    lpAppName = get_c_str(emu, lpAppName)
    lpKeyName = get_stack_arg(emu, 1)
    lpKeyName = get_c_str(emu, lpKeyName)
    lpDefault = get_stack_arg(emu, 2)
    lpDefault = get_c_str(emu, lpDefault)
    out = get_stack_arg(emu, 3)
    sz = get_stack_arg(emu, 4)
    lpFileName = get_stack_arg(emu, 5)
    lpFileName = get_c_str(emu, lpFileName)
    print(f"GetPrivateProfileStringA {lpAppName} {lpKeyName} {lpDefault} {lpFileName}")
    last_error = ERROR_FILE_NOT_FOUND
    return 0

EMU_TABLE = {
    (b'KERNEL32.DLL', b'GetModuleHandleA'): (GetModuleHandleA, 1),
    (b'KERNEL32.DLL', b'GetProcAddress'): (GetProcAddress, 2),
    (b'KERNEL32.DLL', b'GetEnvironmentStrings'): (GetEnvironmentStrings, 0),
    (b'KERNEL32.DLL', b'GetCommandLineA'): (GetCommandLineA, 0),
    (b'KERNEL32.DLL', b'GetVersion'): (GetVersion, 0),
    (b'KERNEL32.DLL', b'GetModuleFileNameA'): (GetModuleFileNameA, 3),
    (b'KERNEL32.DLL', b'VirtualAlloc'): (VirtualAlloc, 4),
    (b'KERNEL32.DLL', b'VirtualFree'): (VirtualFree, 3),
    (b'KERNEL32.DLL', b'GetStdHandle'): (GetStdHandle, 1),
    (b'KERNEL32.DLL', b'ReadFile'): (ReadFile, 5),
    (b'KERNEL32.DLL', b'WriteFile'): (WriteFile, 5),
    (b'KERNEL32.DLL', b'SetFilePointer'): (SetFilePointer, 4),
    (b'KERNEL32.DLL', b'CloseHandle'): (CloseHandle, 1),
    (b'KERNEL32.DLL', b'ExitProcess'): (ExitProcess, 1),
    (b'KERNEL32.DLL', b'SetHandleCount'): (SetHandleCount, 1),
    (b'KERNEL32.DLL', b'GetStartupInfoA'): (GetStartupInfoA, 1),
    (b'KERNEL32.DLL', b'GetFileType'): (GetFileType, 1),
    (b'KERNEL32.DLL', b'SetConsoleCtrlHandler'): (SetConsoleCtrlHandler, 2),
    (b'KERNEL32.DLL', b'GetLocalTime'): (GetLocalTime, 1),
    (b'KERNEL32.DLL', b'GetSystemInfo'): (GetSystemInfo, 1),
    (b'KERNEL32.DLL', b'GetLastError'): (GetLastError, 0),
    (b'KERNEL32.DLL', b'FindFirstFileA'): (FindFirstFileA, 2),
    (b'KERNEL32.DLL', b'FindNextFileA'): (FindNextFileA, 2),
    (b'KERNEL32.DLL', b'FindClose'): (FindClose, 1),
    (b'KERNEL32.DLL', b'GetFileAttributesA'): (GetFileAttributesA, 1),
    (b'KERNEL32.DLL', b'CreateFileA'): (CreateFileA, 7),
    (b'KERNEL32.DLL', b'DeleteFileA'): (DeleteFileA, 1),
    (b'KERNEL32.DLL', b'GetVolumeInformationA'): (GetVolumeInformationA, 8),
    (b'KERNEL32.DLL', b'FileTimeToLocalFileTime'): (FileTimeToLocalFileTime, 2),
    (b'KERNEL32.DLL', b'FileTimeToDosDateTime'): (FileTimeToDosDateTime, 3),
    (b'KERNEL32.DLL', b'GetCurrentDirectoryA'): (GetCurrentDirectoryA, 2),
    (b'KERNEL32.DLL', b'GetFullPathNameA'): (GetFullPathNameA, 4),
    (b'KERNEL32.DLL', b'CreateProcessA'): (CreateProcessA, 10),
    (b'KERNEL32.DLL', b'GetTimeZoneInformation'): (GetTimeZoneInformation, 1),
    (b'KERNEL32.DLL', b'GetPrivateProfileStringA'): (GetPrivateProfileStringA, 6),
}

# load the headers
print(f"Loading 0x{len(pe.header):08x} bytes @ 0x{img_base:08x} (header)")
emu.mem_write(img_base, pe.header)

# load sections
for section in pe.sections:
    addr = img_base + section.VirtualAddress
    data = section.get_data()

    prot = 0
    prot_str = ""
    if section.Characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_READ"]:
        prot |= uc.UC_PROT_READ
        prot_str += "r"
    if section.Characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]:
        prot |= uc.UC_PROT_WRITE
        prot_str += "w"
    if section.Characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]:
        prot |= uc.UC_PROT_EXEC
        prot_str += "x"

    print(f"Loading 0x{len(data):08x} bytes @ 0x{addr:08x} ({prot_str}) ({section.Name.decode('ascii', errors='replace')})")
    emu.mem_write(addr, data)
    emu.mem_protect(addr, section.Misc_VirtualSize, prot)

# imports
imports_table = []
for imp_dir_ent in pe.DIRECTORY_ENTRY_IMPORT:
    # print(imp_dir_ent.dll)
    for imp_ent in imp_dir_ent.imports:
        # print(imp_ent.name, hex(imp_ent.address))
        imports_table.append((imp_dir_ent.dll, imp_ent.name))
syscall_emu_mem = b''
for (i, (dll, fn)) in enumerate(imports_table):
    retn = 0
    bad = "(BAD!)"
    if (dll, fn) in EMU_TABLE:
        retn = EMU_TABLE[(dll, fn)][1]
        bad = ""

    print(f"Emulated function #{i} = {dll.decode('ascii', errors='replace')}!{fn.decode('ascii', errors='replace')} {bad}")
    syscall_emu_mem += struct.pack("<BIBBBH", 0xb8, i, 0x0f, 0x34, 0xc2, retn*4)    # mov eax, imm32    sysenter   retn imm16
assert len(syscall_emu_mem) <= SYSCALL_EMU_SZ
emu.mem_map(SYSCALL_EMU_ADDR, SYSCALL_EMU_SZ, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
emu.mem_write(SYSCALL_EMU_ADDR, syscall_emu_mem)
i = 0
for imp_dir_ent in pe.DIRECTORY_ENTRY_IMPORT:
    for imp_ent in imp_dir_ent.imports:
        emu.mem_write(imp_ent.address, struct.pack("<I", SYSCALL_EMU_ADDR + i*10))
        i += 1

# set up other memory
emu.mem_map(GDT_ADDR, PAGE_SZ, uc.UC_PROT_READ)
emu.mem_write(GDT_ADDR, struct.pack("<QQQQ",
    0,
    0b00000000_1100_1111_10010011_00000000_0000000000000000_1111111111111111,   # data
    0b00000000_1100_1111_10011111_00000000_0000000000000000_1111111111111111,   # code
    0b00000000_1100_1111_10010011_00000000_0000000000000000_1111111111111111 | (TEB_ADDR >> 24 << 56) | (((TEB_ADDR >> 16) & 0xff) << 32),
))
emu.reg_write(ux.UC_X86_REG_GDTR, (0, GDT_ADDR, 4*8-1, 0))
emu.reg_write(ux.UC_X86_REG_SS, 0x08)
emu.reg_write(ux.UC_X86_REG_DS, 0x08)
emu.reg_write(ux.UC_X86_REG_ES, 0x08)
emu.reg_write(ux.UC_X86_REG_GS, 0x08)
emu.reg_write(ux.UC_X86_REG_CS, 0x10)
emu.reg_write(ux.UC_X86_REG_FS, 0x18)

emu.mem_map(STACK_END - STACK_SIZE, STACK_SIZE, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
emu.reg_write(ux.UC_X86_REG_ESP, STACK_END)

emu.mem_map(TEB_ADDR, PAGE_SZ, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
emu.mem_write(TEB_ADDR + 4, struct.pack("<II", STACK_END, STACK_END - STACK_SIZE))
emu.mem_write(TEB_ADDR + 0x18, struct.pack("<I", TEB_ADDR))

# helpers and hooks
def dump_all_registers(emu, dump_eip=False):
    REGS = [
        ('EAX', ux.UC_X86_REG_EAX),
        ('EBX', ux.UC_X86_REG_EBX),
        ('ECX', ux.UC_X86_REG_ECX),
        ('EDX', ux.UC_X86_REG_EDX),
        ('ESI', ux.UC_X86_REG_ESI),
        ('EDI', ux.UC_X86_REG_EDI),
        ('EBP', ux.UC_X86_REG_EBP),
        ('ESP', ux.UC_X86_REG_ESP),
    ]
    for (reg_name, reg_idx) in REGS:
        print(f"\t{reg_name} = 0x{emu.reg_read(reg_idx):08x}")

    if dump_eip:
        print(f"\tEIP = 0x{emu.reg_read(ux.UC_X86_REG_EIP):08x}")

def hook_mem_invalid(emu, access, address, size, value, _user_data):
    eip = emu.reg_read(ux.UC_X86_REG_EIP)

    if access == uc.UC_MEM_WRITE or access == uc.UC_MEM_WRITE_PROT or access == uc.UC_MEM_WRITE_UNMAPPED:
        print(f"invalid WRITE of 0x{address:08x} @ EIP = 0x{eip:08x}, size = {size}, value = {value:x}")
    if access == uc.UC_MEM_READ or access == uc.UC_MEM_READ_PROT or access == uc.UC_MEM_READ_UNMAPPED:
        print(f"invalid READ of 0x{address:08x} @ EIP = 0x{eip:08x}, size = {size}")
    if access == uc.UC_MEM_FETCH or access == uc.UC_MEM_FETCH_PROT or access == uc.UC_MEM_FETCH_UNMAPPED:
        print(f"invalid FETCH of 0x{address:08x} @ EIP = 0x{eip:08x}, size = {size}")

    return False
emu.hook_add(uc.UC_HOOK_MEM_INVALID, hook_mem_invalid)

def hook_sysenter(emu, _user_data):
    eax = emu.reg_read(ux.UC_X86_REG_EAX)
    if eax < len(imports_table):
        emu_func = imports_table[eax]
        retaddr = get_stack_arg(emu, -1)
        if emu_func in EMU_TABLE:
            if TRACE:
                print(f"emulated call! {emu_func[0].decode('ascii', errors='replace')}!{emu_func[1].decode('ascii', errors='replace')}, called @ 0x{retaddr:08x}")
            ret = EMU_TABLE[emu_func][0](emu)
            if TRACE:
                print(f"\tret = 0x{ret:08x}")
            emu.reg_write(ux.UC_X86_REG_EAX, ret)
        else:
            print(f"unhandled import! {emu_func[0].decode('ascii', errors='replace')}!{emu_func[1].decode('ascii', errors='replace')}, called @ 0x{retaddr:08x}")
emu.hook_add(uc.UC_HOOK_INSN, hook_sysenter, aux1=ux.UC_X86_INS_SYSENTER)

def hook_force_no_jit(_emu, _address, _size, _user_data):
    pass
if FORCE_NO_JIT:
    emu.hook_add(uc.UC_HOOK_CODE, hook_force_no_jit, begin=0, end=0xffffffff)


# go go go
ep = img_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f"Emulating code @ 0x{ep:08x}")

try:
    # emulate code in infinite time & unlimited instructions
    emu.emu_start(ep, 0xffffffff)

except uc.UcError as e:
    print("ERROR: %s" % e)
    dump_all_registers(emu, True)
