#!/usr/bin/env python3

import pefile
import struct
import sys
import unicorn as uc
import unicorn.x86_const as ux

from win32 import *

# overall memory map:
# 0x00400000        PE
# 0x7C000000        end of stack
# 0x7c000000        import glue
# 0x7c010000        environment and args
# 0x7c020000        TEB
# 0x7c030000        GDT(?!)

STACK_SIZE = 32*1024*1024
STACK_END = 0x7c000000

SYSCALL_EMU_ADDR = STACK_END

TRACE = False
FORCE_NO_JIT = True

# load the PE
pe = pefile.PE('BC5/BIN/BCC32.EXE')

img_base = pe.OPTIONAL_HEADER.ImageBase
img_sz = pe.OPTIONAL_HEADER.SizeOfImage
if TRACE:
    print(f"Total 0x{img_sz:08x} bytes @ 0x{img_base:08x}")

HEAP_START = (img_base + img_sz + PAGE_SZ - 1) // PAGE_SZ * PAGE_SZ
if TRACE:
    print(f"Free memory starting at 0x{HEAP_START:08x}")

emu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
emu.mem_map(img_base, img_sz, uc.UC_PROT_READ)

# load the headers
if TRACE:
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

    if TRACE:
        print(f"Loading 0x{len(data):08x} bytes @ 0x{addr:08x} ({prot_str}) ({section.Name.decode('ascii', errors='replace')})")
    emu.mem_write(addr, data)
    emu.mem_protect(addr, section.Misc_VirtualSize, prot)

win32ctx = Win32Emu(["bcc32", sys.argv[1:]], [])
end_of_win32_mem = win32ctx.attach_to_emu(emu, SYSCALL_EMU_ADDR, img_base, HEAP_START)

TEB_ADDR = end_of_win32_mem
GDT_ADDR = TEB_ADDR + PAGE_SZ
if TRACE:
    print(f"TEB @ 0x{TEB_ADDR:08x}")
    print(f"GDT @ 0x{GDT_ADDR:08x}")

# imports
for imp_dir_ent in pe.DIRECTORY_ENTRY_IMPORT:
    for imp_ent in imp_dir_ent.imports:
        key = (imp_dir_ent.dll.upper(), imp_ent.name)
        syscall_addr = win32ctx.get_syscall_addr(key)
        if TRACE:
            print(f"{key} @ 0x{syscall_addr:08x} -> 0x{imp_ent.address:08x}")
        emu.mem_write(imp_ent.address, struct.pack("<I", syscall_addr))

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

def hook_force_no_jit(_emu, _address, _size, _user_data):
    pass
if FORCE_NO_JIT:
    emu.hook_add(uc.UC_HOOK_CODE, hook_force_no_jit, begin=0, end=0xffffffff)


# go go go
ep = img_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
if TRACE:
    print(f"Emulating code @ 0x{ep:08x}")

try:
    # emulate code in infinite time & unlimited instructions
    emu.emu_start(ep, 0xffffffff)

except uc.UcError as e:
    print("ERROR: %s" % e)
    dump_all_registers(emu, True)
