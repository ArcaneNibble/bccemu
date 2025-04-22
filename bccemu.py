#!/usr/bin/env python3

import pefile
import struct
import unicorn as uc
import unicorn.x86_const as ux

# overall memory map:
# 0x00400000        PE
# 0x7C000000        end of stack
# 0x7C000000        import glue
# 0x7C010000        TEB
# 0x7C020000        GDT(?!)

PAGE_SZ = 64*1024

STACK_SIZE = 32*1024*1024
STACK_END = 0x7C000000

SYSCALL_EMU_ADDR = STACK_END
SYSCALL_EMU_SZ = PAGE_SZ

TEB_ADDR = SYSCALL_EMU_ADDR + PAGE_SZ
GDT_ADDR = TEB_ADDR + PAGE_SZ

FORCE_NO_JIT = True

# load the PE
pe = pefile.PE('BC5/BIN/BCC32.EXE')

img_base = pe.OPTIONAL_HEADER.ImageBase
img_sz = pe.OPTIONAL_HEADER.SizeOfImage
print(f"Total 0x{img_sz:08x} bytes @ 0x{img_base:08x}")

# syscall emu
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
    module_name = get_stack_arg(emu, 0)
    if module_name == 0:
        ret = img_base
    else:
        module_name = get_c_str(emu, module_name)
        print(f"GetModuleHandleA {module_name.decode('ascii', errors='replace')}")
        ret = 0
    return ret

def GetProcAddress(emu):
    module = get_stack_arg(emu, 0)
    p_name = get_stack_arg(emu, 1)
    name = get_c_str(emu, p_name)
    print(f"GetProcAddress 0x{module:08x}!{name.decode('ascii', errors='replace')}")
    return 0

EMU_TABLE = {
    (b'KERNEL32.DLL', b'GetModuleHandleA'): (GetModuleHandleA, 1),
    (b'KERNEL32.DLL', b'GetProcAddress'): (GetProcAddress, 2),
}

emu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
emu.mem_map(img_base, img_sz, uc.UC_PROT_READ)

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
    if (dll, fn) in EMU_TABLE:
        retn = EMU_TABLE[(dll, fn)][1]

    print(f"Emulated function #{i} = {dll.decode('ascii', errors='replace')}!{fn.decode('ascii', errors='replace')}")
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
            ret = EMU_TABLE[emu_func][0](emu)
            print(f"emulated call! {emu_func[0].decode('ascii', errors='replace')}!{emu_func[1].decode('ascii', errors='replace')}, called @ 0x{retaddr:08x}, ret = 0x{ret:08x}")
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
