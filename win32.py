# Very minimal Win32 emulation

import datetime
import glob
import os
import stat
import struct
import sys
import unicorn as uc
import unicorn.x86_const as ux

TRACE = False

PAGE_SZ = 64*1024

ERROR_FILE_NOT_FOUND = 2
ERROR_INVALID_HANDLE = 6
ERROR_NO_MORE_FILES = 18
ERROR_NOT_SUPPORTED = 50
ERROR_FILE_EXISTS = 80
ERROR_INVALID_PARAMETER = 87
ERROR_MOD_NOT_FOUND = 126
ERROR_PROC_NOT_FOUND = 127
ERROR_INVALID_ADDRESS = 487

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

MAX_PATH = 260

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_NORMAL = 0x80

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

def fn_to_find_data(fn):
    s = os.stat(fn)

    if stat.S_ISDIR(s.st_mode):
        ret = struct.pack("<I", FILE_ATTRIBUTE_DIRECTORY)
    else:
        ret = struct.pack("<I", FILE_ATTRIBUTE_NORMAL)

    # XXX skip timestamps
    ret += b'\x00\x00\x00\x00\x00\x00\x00\x00' * 3
    ret += struct.pack("<IIII", s.st_size >> 32, s.st_size & 0xffffffff, 0, 0)
    ret += fn + b'\x00'
    return ret

class Win32Emu:
    def __init__(self, args, env):
        # win32 global state
        self._last_error = 0
        self._hfile_table = [
            sys.stdin.buffer,
            sys.stdout.buffer,
            sys.stderr.buffer,
        ]
        self._hfind_table = []
        self.exit_code = None

        if len(args) > 0:
            self._argv0 = args[0]
        else:
            self._argv0 = "a"

        env_args = b''

        for env_a in env:
            env_args += env_a.encode()
            env_args += b'\x00'
        env_args += b'\x00'
        self._args_off = len(env_args)

        if len(args) > 0:
            env_args += args[0].encode()
        for arg in args[1:]:
            env_args += (" " + arg).encode()
        env_args += b'\x00'

        if TRACE:
            print(f"Args block: {env_args}")
        self._env_args = env_args

        self._emu_table = [
            ((b'KERNEL32.DLL', b'GetModuleHandleA'), self.GetModuleHandleA, 1),
            ((b'KERNEL32.DLL', b'GetProcAddress'), self.GetProcAddress, 2),
            ((b'KERNEL32.DLL', b'GetEnvironmentStrings'), self.GetEnvironmentStrings, 0),
            ((b'KERNEL32.DLL', b'GetCommandLineA'), self.GetCommandLineA, 0),
            ((b'KERNEL32.DLL', b'GetVersion'), self.GetVersion, 0),
            ((b'KERNEL32.DLL', b'GetModuleFileNameA'), self.GetModuleFileNameA, 3),
            ((b'KERNEL32.DLL', b'VirtualAlloc'), self.VirtualAlloc, 4),
            ((b'KERNEL32.DLL', b'VirtualFree'), self.VirtualFree, 3),
            ((b'KERNEL32.DLL', b'GetStdHandle'), self.GetStdHandle, 1),
            ((b'KERNEL32.DLL', b'ReadFile'), self.ReadFile, 5),
            ((b'KERNEL32.DLL', b'WriteFile'), self.WriteFile, 5),
            ((b'KERNEL32.DLL', b'SetFilePointer'), self.SetFilePointer, 4),
            ((b'KERNEL32.DLL', b'CloseHandle'), self.CloseHandle, 1),
            ((b'KERNEL32.DLL', b'ExitProcess'), self.ExitProcess, 1),
            ((b'KERNEL32.DLL', b'SetHandleCount'), self.SetHandleCount, 1),
            ((b'KERNEL32.DLL', b'GetStartupInfoA'), self.GetStartupInfoA, 1),
            ((b'KERNEL32.DLL', b'GetFileType'), self.GetFileType, 1),
            ((b'KERNEL32.DLL', b'SetConsoleCtrlHandler'), self.SetConsoleCtrlHandler, 2),
            ((b'KERNEL32.DLL', b'GetLocalTime'), self.GetLocalTime, 1),
            ((b'KERNEL32.DLL', b'GetSystemInfo'), self.GetSystemInfo, 1),
            ((b'KERNEL32.DLL', b'GetLastError'), self.GetLastError, 0),
            ((b'KERNEL32.DLL', b'FindFirstFileA'), self.FindFirstFileA, 2),
            ((b'KERNEL32.DLL', b'FindNextFileA'), self.FindNextFileA, 2),
            ((b'KERNEL32.DLL', b'FindClose'), self.FindClose, 1),
            ((b'KERNEL32.DLL', b'GetFileAttributesA'), self.GetFileAttributesA, 1),
            ((b'KERNEL32.DLL', b'CreateFileA'), self.CreateFileA, 7),
            ((b'KERNEL32.DLL', b'DeleteFileA'), self.DeleteFileA, 1),
            ((b'KERNEL32.DLL', b'MoveFileA'), self.MoveFileA, 2),
            ((b'KERNEL32.DLL', b'GetVolumeInformationA'), self.GetVolumeInformationA, 8),
            ((b'KERNEL32.DLL', b'FileTimeToLocalFileTime'), self.FileTimeToLocalFileTime, 2),
            ((b'KERNEL32.DLL', b'FileTimeToDosDateTime'), self.FileTimeToDosDateTime, 3),
            ((b'KERNEL32.DLL', b'GetCurrentDirectoryA'), self.GetCurrentDirectoryA, 2),
            ((b'KERNEL32.DLL', b'GetFullPathNameA'), self.GetFullPathNameA, 4),
            ((b'KERNEL32.DLL', b'CreateProcessA'), self.CreateProcessA, 10),
            ((b'KERNEL32.DLL', b'GetTimeZoneInformation'), self.GetTimeZoneInformation, 1),
            ((b'KERNEL32.DLL', b'GetPrivateProfileStringA'), self.GetPrivateProfileStringA, 6),
            ((b'KERNEL32.DLL', b'GlobalMemoryStatus'), self.GlobalMemoryStatus, 1),
            ((b'KERNEL32.DLL', b'InitializeCriticalSection'), self.InitializeCriticalSection, 1),
            ((b'KERNEL32.DLL', b'EnterCriticalSection'), self.EnterCriticalSection, 1),
            ((b'KERNEL32.DLL', b'LeaveCriticalSection'), self.LeaveCriticalSection, 1),
            ((b'KERNEL32.DLL', b'GetCurrentProcessId'), self.GetCurrentProcessId, 0),
            ((b'KERNEL32.DLL', b'GetCurrentThreadId'), self.GetCurrentThreadId, 0),
            ((b'KERNEL32.DLL', b'GetConsoleMode'), self.GetConsoleMode, 2),
        ]
        self._emu_table_map = {}
        for (i, (key, _fn, _nargs)) in enumerate(self._emu_table):
            self._emu_table_map[key] = i

    def attach_to_emu(self, emu, base_addr, img_base, heap_start):
        self._img_base = img_base
        self._heap_addr = heap_start

        # syscall emulation page
        syscall_emu_mem = b''
        for (i, ((dll, fn_name), fn, nargs)) in enumerate(self._emu_table):
            if TRACE:
                print(f"Emulated function #{i} = {dll.decode('ascii', errors='replace')}!{fn_name.decode('ascii', errors='replace')}")
            syscall_emu_mem += struct.pack("<BIBBBH", 0xb8, i, 0x0f, 0x34, 0xc2, nargs*4)   # mov eax, imm32    sysenter   retn imm16
        invalid_syscall_offs = len(syscall_emu_mem)
        syscall_emu_mem += b'\xcc'

        self._syscall_page_addr = base_addr
        self._syscall_invalid_addr = self._syscall_page_addr + invalid_syscall_offs
        syscall_emu_sz = (len(syscall_emu_mem) + PAGE_SZ - 1) // PAGE_SZ * PAGE_SZ
        emu.mem_map(self._syscall_page_addr, syscall_emu_sz, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
        emu.mem_write(self._syscall_page_addr, syscall_emu_mem)

        # args and environment
        self._env_ptr = self._syscall_page_addr + syscall_emu_sz
        self._args_ptr = self._env_ptr + self._args_off
        env_args_real_sz = (len(self._env_args) + PAGE_SZ - 1) // PAGE_SZ * PAGE_SZ
        emu.mem_map(self._env_ptr, env_args_real_sz, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        emu.mem_write(self._env_ptr, self._env_args)

        if TRACE:
            print(f"syscall page @ 0x{self._syscall_page_addr:08x}")
            print(f"environ page @ 0x{self._env_ptr:08x}")

        # connect!
        emu.hook_add(uc.UC_HOOK_INSN, self.hook_sysenter, aux1=ux.UC_X86_INS_SYSENTER)

        return self._env_ptr + env_args_real_sz

    def hook_sysenter(self, emu, _user_data):
        eax = emu.reg_read(ux.UC_X86_REG_EAX)
        if eax < len(self._emu_table):
            emu_func = self._emu_table[eax]
            retaddr = get_stack_arg(emu, -1)
            if TRACE:
                print(f"emulated call! {emu_func[0][0].decode('ascii', errors='replace')}!{emu_func[0][1].decode('ascii', errors='replace')}, called @ 0x{retaddr:08x}")
            ret = emu_func[1](emu)
            if TRACE:
                print(f"\tret = 0x{ret:08x}")
            emu.reg_write(ux.UC_X86_REG_EAX, ret)
    
    def get_syscall_addr(self, key):
        if key not in self._emu_table_map:
            return (self._syscall_invalid_addr, False)
        return (self._syscall_page_addr + 10*self._emu_table_map[key], True)

    def GetModuleHandleA(self, emu):
        module_name = get_stack_arg(emu, 0)
        if module_name == 0:
            return self._img_base
        else:
            module_name = get_c_str(emu, module_name)

            if module_name.upper() == b'KERNEL32.DLL':
                return self._syscall_page_addr

            print(f"GetModuleHandleA {module_name.decode('ascii', errors='replace')} (UNIMPL!)")
            self._last_error = ERROR_MOD_NOT_FOUND
            return 0

    def GetProcAddress(self, emu):
        module = get_stack_arg(emu, 0)
        p_name = get_stack_arg(emu, 1)
        name = get_c_str(emu, p_name)

        if TRACE:
            print(f"GetProcAddress 0x{module:08x}!{name.decode('ascii', errors='replace')} (DUMMY)")

        if module == self._syscall_page_addr:
            try:
                key = (b'KERNEL32.DLL', name)
                idx = next(i for i,v in enumerate(self._emu_table) if v[0] == key)
                return self._syscall_page_addr + idx*10
            except StopIteration:
                pass

        self._last_error = ERROR_PROC_NOT_FOUND
        return 0

    def GetEnvironmentStrings(self, emu):
        return self._env_ptr

    def GetCommandLineA(self, emu):
        return self._args_ptr

    def GetVersion(self, emu):
        return 0x0105   # winxp (5.1)

    def GetModuleFileNameA(self, emu):
        module = get_stack_arg(emu, 0)
        out_fn = get_stack_arg(emu, 1)
        out_sz = get_stack_arg(emu, 2)
        if module == 0:
            # XXX this path is hardcoded
            filename = b"C:\\BC5\\BIN\\" + self._argv0.upper().encode() + b".EXE\x00"
            sz = min(out_sz, len(filename))
            if TRACE:
                print(f"GetModuleFileNameA write to 0x{out_fn:08x} sz 0x{sz:x} orig_sz 0x{out_sz:x}")
            emu.mem_write(out_fn, filename[:sz])
            return len(filename) - 1

        self._last_error = ERROR_MOD_NOT_FOUND
        return 0

    def VirtualAlloc(self, emu):
        addr = get_stack_arg(emu, 0)
        sz = get_stack_arg(emu, 1)
        ty = get_stack_arg(emu, 2)
        prot = get_stack_arg(emu, 3)

        if (ty & MEM_COMMIT) and not (ty & MEM_RESERVE) and addr:
            if TRACE:
                print(f"VirtualAlloc @ 0x{addr:08x} sz 0x{sz:08x} type 0x{ty:08x} prot 0x{prot:08x} (COMMIT)")
            return addr

        # we don't support mapping fixed addresses, only ones chosen by our basic bump allocator
        if addr:
            self._last_error = ERROR_INVALID_ADDRESS
            return 0

        if TRACE:
            print(f"VirtualAlloc @ 0x{addr:08x} sz 0x{sz:08x} type 0x{ty:08x} prot 0x{prot:08x}")

        addr = self._heap_addr
        if sz == 0:
            sz = 1
        real_sz = (sz + PAGE_SZ - 1) // PAGE_SZ * PAGE_SZ
        self._heap_addr += real_sz

        # XXX we ignore type and prot, and just give it read/write
        emu.mem_map(addr, real_sz, uc.UC_PROT_READ | uc.UC_PROT_WRITE)

        return addr

    def VirtualFree(self, emu):
        addr = get_stack_arg(emu, 0)
        sz = get_stack_arg(emu, 1)
        ty = get_stack_arg(emu, 2)

        if TRACE:
            print(f"VirtualFree @ 0x{addr:08x} sz 0x{sz:08x} type 0x{ty:08x} (DUMMY)")
        return 1

    def GetStdHandle(self, emu):
        std_handle = get_stack_arg(emu, 0)

        if TRACE:
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

        self._last_error = ERROR_INVALID_HANDLE
        return 0xffffffff

    def ReadFile(self, emu):
        hfile = get_stack_arg(emu, 0)
        buffer = get_stack_arg(emu, 1)
        sz = get_stack_arg(emu, 2)
        read = get_stack_arg(emu, 3)
        overlapped = get_stack_arg(emu, 4)

        if overlapped:
            self._last_error = ERROR_NOT_SUPPORTED
            return 0

        if hfile >> 2 >= len(self._hfile_table):
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        ioio = self._hfile_table[hfile >> 2]
        if ioio is None:
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        buf = ioio.read(sz)

        emu.mem_write(buffer, buf)

        if read:
            emu.mem_write(read, struct.pack("<I", len(buf)))
        return 1

    def WriteFile(self, emu):
        hfile = get_stack_arg(emu, 0)
        buffer = get_stack_arg(emu, 1)
        sz = get_stack_arg(emu, 2)
        written = get_stack_arg(emu, 3)
        overlapped = get_stack_arg(emu, 4)

        buf = emu.mem_read(buffer, sz)

        if overlapped:
            self._last_error = ERROR_NOT_SUPPORTED
            return 0

        if hfile >> 2 >= len(self._hfile_table):
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        ioio = self._hfile_table[hfile >> 2]
        if ioio is None:
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        ioio.write(buf)

        if written:
            emu.mem_write(written, struct.pack("<I", sz))
        return 1

    def SetFilePointer(self, emu):
        hfile = get_stack_arg(emu, 0)
        dist_lo = get_stack_arg(emu, 1)
        pdist_hi = get_stack_arg(emu, 2)
        method = get_stack_arg(emu, 3)

        if hfile >> 2 >= len(self._hfile_table):
            self._last_error = ERROR_INVALID_HANDLE
            return 0
        
        ioio = self._hfile_table[hfile >> 2]
        if ioio is None:
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        if pdist_hi:
            dist_hi = struct.unpack("<I", emu.mem_read(pdist_hi, 4))[0]
            dist_ = (dist_hi << 32) | dist_lo
            if dist_ & 0x80000000_00000000:
                dist = dist_ - 0x1_00000000_00000000
            else:
                dist = dist_
        else:
            if dist_lo & 0x80000000:
                dist = dist_lo - 0x1_0000_0000
            else:
                dist = dist_lo

        if TRACE:
            print(f"SetFilePointer {ioio} disp {dist} method {method}")
        ioio.seek(dist, method)
        pos = ioio.tell()

        if pdist_hi:
            emu.mem_write(pdist_hi, struct.pack("<I", pos >> 32))
        return pos & 0xffffffff

    def CloseHandle(self, emu):
        hfile = get_stack_arg(emu, 0)

        if hfile >> 2 >= len(self._hfile_table):
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        if hfile >> 2 >= 2:
            ioio = self._hfile_table[hfile >> 2]
            if ioio is None:
                self._last_error = ERROR_INVALID_HANDLE
                return 0

            self._hfile_table[hfile >> 2].close()
            self._hfile_table[hfile >> 2] = None
        return 1

    def ExitProcess(self, emu):
        code = get_stack_arg(emu, 0)
        self.exit_code = code
        if TRACE:
            print(f"Process executed with status: {code}")
        emu.mem_write(emu.reg_read(ux.UC_X86_REG_ESP), b'\xff\xff\xff\xff')
        return 0

    def SetHandleCount(self, emu):
        return get_stack_arg(emu, 0)

    def GetStartupInfoA(self, emu):
        info = get_stack_arg(emu, 0)
        # TODO (maybe): subprocess handling?
        emu.mem_write(info, struct.pack("<IIIIIIIIIIIIHHIIII", 17*4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return 0

    def GetFileType(self, emu):
        hfile = get_stack_arg(emu, 0)

        if hfile >> 2 >= len(self._hfile_table):
            self._last_error = ERROR_INVALID_HANDLE
            return 0
        
        ioio = self._hfile_table[hfile >> 2]

        if ioio.isatty():
            return 2
        if not ioio.seekable():
            return 3
        return 1

    def SetConsoleCtrlHandler(self, emu):
        fn = get_stack_arg(emu, 0)
        add = get_stack_arg(emu, 1)
        if TRACE:
            print(f"SetConsoleCtrlHandler {"add" if add else "del"} @ 0x{fn:08x} (DUMMY)")
        return 1

    def GetLocalTime(self, emu):
        dt = datetime.datetime.now()
        info = get_stack_arg(emu, 0)
        emu.mem_write(info, struct.pack("<HHHHHHHH", dt.year, dt.month, (dt.weekday() + 1) % 7, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond // 1000))
        return 0

    def GetSystemInfo(self, emu):
        info = get_stack_arg(emu, 0)
        emu.mem_write(info, struct.pack("<HHIIIIIIIHH", 0, 0, PAGE_SZ, 0, 0xffffffff, 1, 1, 586, PAGE_SZ, 6, 0))
        return 0

    def GetLastError(self, emu):
        return self._last_error

    def FindFirstFileA(self, emu):
        p_fn = get_stack_arg(emu, 0)
        fn = get_c_str(emu, p_fn)
        out = get_stack_arg(emu, 1)

        if TRACE:
            print(f"FindFirstFileA {fn}")

        files = glob.glob(fn)
        if len(files) == 0:
            self._last_error = ERROR_FILE_NOT_FOUND
            return 0xffffffff

        find_data = fn_to_find_data(files[0])
        emu.mem_write(out, find_data)

        hfind = len(self._hfind_table) << 2
        self._hfind_table.append(files[1:])
        return hfind

    def FindNextFileA(self, emu):
        hfind = get_stack_arg(emu, 0) >> 2
        out = get_stack_arg(emu, 1)

        if hfind >= len(self._hfind_table):
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        files = self._hfind_table[hfind >> 2]
        if TRACE:
            print(f"FindNextFileA {files}")

        if files is None:
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        if len(files) == 0:
            self._last_error = ERROR_NO_MORE_FILES
            return 0

        find_data = fn_to_find_data(files[0])
        emu.mem_write(out, find_data)
        self._hfind_table[hfind >> 2] = files[1:]
        return 1

    def FindClose(self, emu):
        hfind = get_stack_arg(emu, 0) >> 2

        if hfind >= len(self._hfind_table):
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        files = self._hfind_table[hfind >> 2]
        if files is None:
            self._last_error = ERROR_INVALID_HANDLE
            return 0

        self._hfind_table[hfind >> 2] = None
        return 1

    def GetFileAttributesA(self, emu):
        p_fn = get_stack_arg(emu, 0)
        fn = get_c_str(emu, p_fn)

        if TRACE:
            print(f"GetFileAttributesA {fn}")

        # HACK
        if fn.startswith(b'Z:\\'):
            return FILE_ATTRIBUTE_NORMAL

        self._last_error = ERROR_NOT_SUPPORTED
        try:
            s = os.stat(fn)
            if stat.S_ISDIR(s.st_mode):
                return FILE_ATTRIBUTE_DIRECTORY
            else:
                return FILE_ATTRIBUTE_NORMAL
        except FileNotFoundError:
            self._last_error = ERROR_FILE_NOT_FOUND
        return 0xffffffff

    def CreateFileA(self, emu):
        p_fn = get_stack_arg(emu, 0)
        fn = get_c_str(emu, p_fn)
        dwDesiredAccess = get_stack_arg(emu, 1)
        dwShareMode = get_stack_arg(emu, 2)
        lpSecurityAttributes = get_stack_arg(emu, 3)
        dwCreationDisposition = get_stack_arg(emu, 4)
        dwFlagsAndAttributes = get_stack_arg(emu, 5)
        hTemplateFile = get_stack_arg(emu, 6)
        if TRACE:
            print(f"CreateFileA {fn} {dwCreationDisposition}")

        # not very accurate emulation lol
        if dwCreationDisposition == 1 or dwCreationDisposition == 2 or dwCreationDisposition == 5:
            mode = 'w+b'
        elif dwCreationDisposition == 3 or dwCreationDisposition == 4:
            mode = 'r+b'
        else:
            self._last_error = ERROR_INVALID_PARAMETER
            return 0xffffffff

        try:
            ioio = open(fn, mode)
        except FileNotFoundError:
            self._last_error = ERROR_FILE_NOT_FOUND
            return 0xffffffff
        
        hfile = len(self._hfile_table) << 2
        self._hfile_table.append(ioio)
        return hfile

    def DeleteFileA(self, emu):
        p_fn = get_stack_arg(emu, 0)
        fn = get_c_str(emu, p_fn)
        if TRACE:
            print(f"DeleteFileA {fn} (DUMMY)")

        self._last_error = ERROR_NOT_SUPPORTED
        try:
            os.unlink(fn)
            return 1
        except FileNotFoundError:
            self._last_error = ERROR_FILE_NOT_FOUND
        return 0

    def MoveFileA(self, emu):
        p_existing = get_stack_arg(emu, 0)
        existing = get_c_str(emu, p_existing)
        p_new = get_stack_arg(emu, 1)
        new = get_c_str(emu, p_new)
        if TRACE:
            print(f"MoveFileA {existing} -> {new}")

        self._last_error = ERROR_NOT_SUPPORTED
        try:
            os.rename(existing, new)
            return 1
        except FileNotFoundError:
            self._last_error = ERROR_FILE_NOT_FOUND
        except FileExistsError:
            self._last_error = ERROR_FILE_EXISTS
        return 0

    def GetVolumeInformationA(self, emu):
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
            if TRACE:
                print(f"GetVolumeInformationA retrieving name")
            emu.mem_write(lpVolumeNameBuffer, volname[:sz])
        if lpVolumeSerialNumber:
            if TRACE:
                print(f"GetVolumeInformationA retrieving serial")
            emu.mem_write(lpVolumeSerialNumber, b'\xde\xad\xbe\xef')
        if lpMaximumComponentLength:
            if TRACE:
                print(f"GetVolumeInformationA retrieving max path component")
            emu.mem_write(lpMaximumComponentLength, struct.pack("<I", 255))
        if lpFileSystemFlags:
            if TRACE:
                print(f"GetVolumeInformationA retrieving flags")
            emu.mem_write(lpFileSystemFlags, struct.pack("<I", 0x6))
        if lpFileSystemNameBuffer:
            fsname = b"EMU\x00"
            sz = min(nFileSystemNameSize, len(fsname))
            if TRACE:
                print(f"GetVolumeInformationA retrieving fs")
            emu.mem_write(lpFileSystemNameBuffer, fsname[:sz])

        return 1

    def FileTimeToLocalFileTime(self, emu):
        inp = get_stack_arg(emu, 0)
        outp = get_stack_arg(emu, 1)
        # TODO
        emu.mem_write(outp, b'\x00\x00\x00\x00\x00\x00\x00\x00')
        return 1

    def FileTimeToDosDateTime(self, emu):
        inp = get_stack_arg(emu, 0)
        outp_date = get_stack_arg(emu, 1)
        outp_time = get_stack_arg(emu, 1)
        # TODO
        emu.mem_write(outp_date, b'\x00\x00\x00\x00')
        emu.mem_write(outp_time, b'\x00\x00\x00\x00')
        return 1

    def GetCurrentDirectoryA(self, emu):
        sz = get_stack_arg(emu, 0)
        buf = get_stack_arg(emu, 1)

        fake_cur_dir = b"Z:\\\x00"
        sz = min(sz, len(fake_cur_dir))
        emu.mem_write(buf, fake_cur_dir[:sz])
        return len(fake_cur_dir)

    def GetFullPathNameA(self, emu):
        inp = get_stack_arg(emu, 0)
        inp = get_c_str(emu, inp)
        bufsz = get_stack_arg(emu, 1)
        buf = get_stack_arg(emu, 2)
        p_fn = get_stack_arg(emu, 3)
        print(f"GetFullPathNameA {inp} (UNIMPL!)")
        return 0

    def CreateProcessA(self, emu):
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

    def GetTimeZoneInformation(self, emu):
        return 0xffffffff

    def GetPrivateProfileStringA(self, emu):
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

        if TRACE:
            print(f"GetPrivateProfileStringA {lpAppName} {lpKeyName} {lpDefault} {lpFileName}")
        real_sz = min(sz - 1, len(lpDefault))
        emu.mem_write(out, lpDefault[:real_sz])
        emu.mem_write(out + real_sz, b'\x00')
        self._last_error = ERROR_FILE_NOT_FOUND
        return real_sz

    def GlobalMemoryStatus(self, emu):
        info = get_stack_arg(emu, 0)
        emu.mem_write(info, struct.pack("<IIIIIIII", 8*4, 0, 0x80000000, 0x80000000, 0, 0, 0x80000000, 0x80000000))
        return 0

    def InitializeCriticalSection(self, emu):
        return 0
    def EnterCriticalSection(self, emu):
        return 0
    def LeaveCriticalSection(self, emu):
        return 0

    def GetCurrentProcessId(self, emu):
        return 1
    def GetCurrentThreadId(self, emu):
        return 1

    def GetConsoleMode(self, emu):
        return 0
