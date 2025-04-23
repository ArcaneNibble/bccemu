#!/usr/bin/env python3

import binascii
import pathlib
import pefile
import struct
import sys
import unicorn as uc
import unicorn.x86_const as ux

from win32 import Win32Emu, PAGE_SZ

DIR_FOR_THIS_SCRIPT = str(pathlib.Path(__file__).parent.resolve())

# overall memory map:
# 0x00400000        PE
# 0x7c000000        end of stack
# 0x7c000000        import glue
# 0x7c010000        environment and args
# 0x7c020000        TEB
# 0x7c030000        GDT(?!)

STACK_SIZE = 32*1024*1024
STACK_END = 0x7c000000

SYSCALL_EMU_ADDR = STACK_END

TRACE = False
FORCE_NO_JIT = False


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

    stackdump = emu.mem_read(emu.reg_read(ux.UC_X86_REG_ESP), 32)
    print(f"\tStack dump: {binascii.hexlify(stackdump)}")

def hook_mem_invalid(emu, access, address, size, value, _user_data):
    eip = emu.reg_read(ux.UC_X86_REG_EIP)

    if access == uc.UC_MEM_WRITE or access == uc.UC_MEM_WRITE_PROT or access == uc.UC_MEM_WRITE_UNMAPPED:
        print(f"invalid WRITE of 0x{address:08x} @ EIP = 0x{eip:08x}, size = {size}, value = {value:x}")
    if access == uc.UC_MEM_READ or access == uc.UC_MEM_READ_PROT or access == uc.UC_MEM_READ_UNMAPPED:
        print(f"invalid READ of 0x{address:08x} @ EIP = 0x{eip:08x}, size = {size}")
    if access == uc.UC_MEM_FETCH or access == uc.UC_MEM_FETCH_PROT or access == uc.UC_MEM_FETCH_UNMAPPED:
        print(f"invalid FETCH of 0x{address:08x} @ EIP = 0x{eip:08x}, size = {size}")

    return False


def hook_force_no_jit(_emu, _address, _size, _user_data):
    pass


class PEEmu:
    def __init__(self, args, env):
        # load the PE
        pe = pefile.PE(DIR_FOR_THIS_SCRIPT + '/BC5/BIN/' + args[0].upper() + '.EXE')

        self._img_base = pe.OPTIONAL_HEADER.ImageBase
        img_sz = pe.OPTIONAL_HEADER.SizeOfImage
        if TRACE:
            print(f"Total 0x{img_sz:08x} bytes @ 0x{self._img_base:08x}")

        emu = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        emu.mem_map(self._img_base, img_sz, uc.UC_PROT_READ)

        # load the headers
        if TRACE:
            print(f"Loading 0x{len(pe.header):08x} bytes @ 0x{self._img_base:08x} (header)")
        emu.mem_write(self._img_base, pe.header)

        # load sections
        for section in pe.sections:
            addr = self._img_base + section.VirtualAddress
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

        heap_start = (self._img_base + img_sz + PAGE_SZ - 1) // PAGE_SZ * PAGE_SZ
        if TRACE:
            print(f"Free memory starting at 0x{heap_start:08x}")

        win32ctx = Win32Emu(args, env)
        self._win32 = win32ctx
        end_of_win32_mem = win32ctx.attach_to_emu(emu, SYSCALL_EMU_ADDR, self._img_base, heap_start)

        # imports
        for imp_dir_ent in pe.DIRECTORY_ENTRY_IMPORT:
            for imp_ent in imp_dir_ent.imports:
                key = (imp_dir_ent.dll.upper(), imp_ent.name)
                (syscall_addr, valid) = win32ctx.get_syscall_addr(key)
                if TRACE:
                    print(f"{key} @ 0x{syscall_addr:08x} -> 0x{imp_ent.address:08x}")
                    if not valid:
                        print(f"WARN: {key} NOT IMPLEMENTED!")
                emu.mem_write(imp_ent.address, struct.pack("<I", syscall_addr))

        # set up other memory
        teb_addr = end_of_win32_mem
        gdt_addr = teb_addr + PAGE_SZ
        if TRACE:
            print(f"TEB @ 0x{teb_addr:08x}")
            print(f"GDT @ 0x{gdt_addr:08x}")

        emu.mem_map(gdt_addr, PAGE_SZ, uc.UC_PROT_READ)
        emu.mem_write(gdt_addr, struct.pack("<QQQQ",
            0,
            0b00000000_1100_1111_10010011_00000000_0000000000000000_1111111111111111,   # data
            0b00000000_1100_1111_10011111_00000000_0000000000000000_1111111111111111,   # code
            0b00000000_1100_1111_10010011_00000000_0000000000000000_1111111111111111 | (teb_addr >> 24 << 56) | (((teb_addr >> 16) & 0xff) << 32),
        ))
        emu.reg_write(ux.UC_X86_REG_GDTR, (0, gdt_addr, 4*8-1, 0))
        emu.reg_write(ux.UC_X86_REG_SS, 0x08)
        emu.reg_write(ux.UC_X86_REG_DS, 0x08)
        emu.reg_write(ux.UC_X86_REG_ES, 0x08)
        emu.reg_write(ux.UC_X86_REG_GS, 0x08)
        emu.reg_write(ux.UC_X86_REG_CS, 0x10)
        emu.reg_write(ux.UC_X86_REG_FS, 0x18)

        emu.mem_map(STACK_END - STACK_SIZE, STACK_SIZE, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        emu.reg_write(ux.UC_X86_REG_ESP, STACK_END)

        emu.mem_map(teb_addr, PAGE_SZ, uc.UC_PROT_READ | uc.UC_PROT_WRITE)
        emu.mem_write(teb_addr + 4, struct.pack("<II", STACK_END, STACK_END - STACK_SIZE))
        emu.mem_write(teb_addr + 0x18, struct.pack("<I", teb_addr))

        self._ep = self._img_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

        emu.hook_add(uc.UC_HOOK_MEM_INVALID, hook_mem_invalid)
        emu.hook_add(uc.UC_HOOK_CODE, hook_force_no_jit, begin=SYSCALL_EMU_ADDR, end=0xffffffff)
        if FORCE_NO_JIT:
            emu.hook_add(uc.UC_HOOK_CODE, hook_force_no_jit, begin=0, end=0xffffffff)

        self._emu = emu

    def run(self):
        if TRACE:
            print(f"Emulating code @ 0x{self._ep:08x}")

        try:
            self._emu.emu_start(self._ep, 0xffffffff)
        except uc.UcError as e:
            print("ERROR: %s" % e)
            dump_all_registers(self._emu, True)
            return -1

        return self._win32.exit_code


def main():
    args = sys.argv
    if args[0].endswith(".py"):
        args = args[1:]

    if not len(args):
        print(f"Usage: bccemu.py tool [tool_args...]")
        sys.exit(-1)

    emu = PEEmu(args, [])
    ret = emu.run()
    sys.exit(ret)


if __name__=='__main__':
    main()
