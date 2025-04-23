# Borland C++ emulator

Emulator to run Borland C++ command-line tools on any platform which supports Python and [Unicorn Engine](https://www.unicorn-engine.org/).

```text
$ ./bcc32
Borland C++ 5.0 for Win32 Copyright (c) 1993, 1996 Borland International
Syntax is: BCC32 [ options ] file[s]     * = default; -x- = turn switch x off
  -3    * 80386 Instructions        -4      80486 Instructions
  -Ax     Disable extensions        -B      Compile via assembly
  -C      Allow nested comments     -Dxxx   Define macro
  -Exxx   Alternate Assembler name  -Hxxx   Use pre-compiled headers
  -Ixxx   Include files directory   -K      Default char is unsigned
  -Lxxx   Libraries directory       -M      Generate link map
  -N      Check stack overflow      -Ox     Optimizations
  -P      Force C++ compile         -R      Produce browser info
  -RT   * Generate RTTI             -S      Produce assembly output
  -Txxx   Set assembler option      -Uxxx   Undefine macro
  -Vx     Virtual table control     -X      Suppress autodep. output
  -aN     Align on N bytes          -b    * Treat enums as integers
  -c      Compile only              -d      Merge duplicate strings
  -exxx   Executable file name      -fxx    Floating point options
  -gN     Stop after N warnings     -iN     Max. identifier length
  -jN     Stop after N errors       -k    * Standard stack frame
  -lx     Set linker option         -nxxx   Output file directory
  -oxxx   Object file name          -p      Pascal calls
  -tWxxx  Create Windows app        -u    * Underscores on externs
  -v      Source level debugging    -wxxx   Warning control
  -xxxx   Exception handling        -y      Produce line number info
  -zxxx   Set segment names

$ ./tlink32
Turbo Link  Version 1.6.71.0 Copyright (c) 1993,1996 Borland International
Syntax: TLINK32 objfiles, exefile, mapfile, libfiles, deffile, resfiles
@xxxx indicates use response file xxxx
  -m      Map file with publics     -x       No map
  -s      Detailed segment map      -L       Specify library search paths
  -M      Map with mangled names    -j       Specify object search paths
  -c      Case sensitive link       -v       Full symbolic debug information
  -Enn    Max number of errors      -n       No default libraries
  -P-     Disable code packing      -H:xxxx  Specify app heap reserve size
  -B:xxxx Specify image base addr   -Hc:xxxx Specify app heap commit size
  -wxxx   Warning control           -S:xxxx  Specify app stack reserve size
  -Txx    Specify output file type  -Sc:xxxx Specify app stack commit size
          -Tpx  PE image            -Af:nnnn Specify file alignment
                (x: e=EXE, d=DLL)   -Ao:nnnn Specify object alignment
  -ax     Specify application type  -o       Import by ordinals
          -ap Windowing Compatible  -Vd.d    Specify Windows version
          -aa Uses Windowing API    -r       Verbose link
```

This contains the barest minimum needed to emulate `bcc32.exe` and `tlink32.exe`. Other utilities such as `tdump.exe` _might_ work.

## NOTES

`CreateProcess` isn't implemented, so `bcc32` cannot invoke the linker directly. You need to manually run the compiler with `-c` and the linker separately.

`C:` is emulated to be this Python module's directory, and `Z:` is the current working directory. You'll need to manually specify `-I` and `-L` as well because it doesn't seem to load the `.cfg` files for some reason.

Note that the _commas_ in `tlink32` are *important*! It is _very_ much not *nix-style tooling.

## Example

```text
$ cat test.c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    MessageBox(0, "Hello world!", "OwO?", 0);
    return 42;
}

$ ./bcc32 -IC:\\BC5\\INCLUDE -c test.c
$ ./tlink32 -LC:\\BC5\\LIB -c -aa -Tpe c0w32.obj test.obj , test.exe ,, import32.lib cw32.lib

$ file test.exe
test.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```
