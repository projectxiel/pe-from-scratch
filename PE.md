- [Intro](#intro)
- [Testing Different Compilers](#testing-different-compilers)
  * [Runtimes](#runtimes)
- [Assembly](#assembly)
- [The PE Format](#the-pe-format)
  * [DosHeader and DosStub](#dosheader-and-dosstub)
  * [NT Headers](#nt-headers)
  * [File Header](#file-header)
  * [Optional Header](#optional-header)
- [Section Headers](#section-headers)
- [Sections](#sections)
  * [Data Section](#data-section)
  * [The Executable Section](#the-executable-section)
  * [PUSH Instruction Encoding Table](#push-instruction-encoding-table)
    + [Legend](#legend)
  * [CALL—Call Procedure](#callcall-procedure)
    + [Instruction Operand Encoding](#instruction-operand-encoding)
    + [Legend](#legend-1)
  * [ModR/M Byte Structure](#modrm-byte-structure)
  * [Import Section](#import-section)
- [Wrapping Up](#wrapping-up)
- [References](#references)
# Intro

Have you ever wondered how executables on Windows work? No? I'm gonna talk about it anyways. Today I'm here to talk about the Portable Executable Format, usually just shortened to PE. And by the end of this article, we'll have reconstructed a binary, mostly from scratch. 

What actually got me insterested in this topic initally was the fact that I was working on a compiler, which turned into me working on an assembler, which turned into me having to understand how executables work.

Since I use Windows as my main machine, (niche gaming operating system), that's the platform I need to focus on. I prefer ELF as a bianry format, but 90 percent of people still use Windows, so I assume its a pretty important platform to wrap my head around.

There were a few ways I thought about aproaching this project. The main goal was to understand how each byte in an executable played a role.

We could try to manually create a "Hello World" program in a hex editor byte by byte, but not only is that tedious and error prone, I just don't feel like doing that. So instead, I'm gonna do the next best thing, write a program that writes the specific bytes that I want to a file, until I get a working executable. Which is actually far simpler.

# Testing Different Compilers

Before that though, I think its best if we don't go in completely blind, so I thought I'd try compiling "Hello World" in every compiled language I had on my machine. In the end I compiled C, Haskell, Odin, Rust, Zig, and Go. C++ with gcc wasn't working on my machine for some reason, so I gave up on it, even though I could've probably just used clang.

I also noticed that compiling the same binary with clang and gcc netted different results. Binaries compiled with clang were larger for some reason.

Every executable was different in size, despite doing basically the same thing. There's no point in showing the code for these programs, because you've probably already seen it before. Its just "Hello World" after all. But I will show the different sizes for the binaries in a table.

| Filename   | Size (Bytes) | Date       | Time   |
|------------|--------------|------------|--------|
| c.exe      | 55,165       | Dec 24     | 15:15  |
| cc.exe     | 137,728      | Jan 3      | 12:12  |
| goe.exe    | 2,224,128    | Dec 24     | 14:20  |
| hs.exe     | 11,690,496   | Dec 24     | 14:17  |
| odine.exe  | 550,912      | Dec 24     | 14:16  |
| rs.exe     | 163,840      | Dec 24     | 14:18  |
| zige.exe   | 633,344      | Dec 24     | 14:19  |

Predictably C ended up being the smallest, everything else ranged from 100KB to 11MB in size. The file labeled `cc.exe` is not C++, its actually C compiled with clang instead of gcc, and surprisingly its more than double the size of the gcc version, interesting.

What was more surpising though was how Go and Haskell were 2MB and 11.7 MB respectively. There are compilers that are smaller than these "Hello World" programs, (very few, but they do exist). For instance, the latest release of Odin, at the time of me writing this article is only 2.5 MB on Windows. The reason why is obvious though. Runtimes. Well... also debug symbols. 

Technically there are ways to drastically decrease the size of each binary in each language with special directives and build flags, but I didn't feel like doing that, because that would just distract me from what I'm trying to do.

## Runtimes

Generally speaking, the more complicated the language the more complicated the runtime. A runtime is basically the program that implements the rules of the program, or if we want to be more correct, it could be described as the instructions added to the binary by the compiler that you didn't explicitly add yourself that implement the rules of the language. 

For garbage collected languages, runtimes are especially large, because they have to do a lot more work, they're basically doing book keeping for entire lifetime of the program. This likely also explains why Zig and Odin are so much larger aswell, they're runtimes are more complex than C, surprisingly though, Rust's binary is actually quite small.

Doing a hexdump of one of these is pretty surprising.
`c.exe (54 Kb)`
```
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
(~3,400 lines more)
0000d760  5f 5f 70 5f 5f 5f 77 61  72 67 76 00 5f 5f 6d 69  |__p___wargv.__mi|
0000d770  6e 67 77 5f 61 70 70 5f  74 79 70 65 00           |ngw_app_type.|
0000d77d
```

It makes sense that it would be this big. Afterall 55,165 bytes is a lot of bytes. At first glance we can see a lot of the different sections, .text, .data, .rdata, .pdata ect. Theres also text at the top that says "This program cannot be run in DOS Mode.", we'll talk about what that means a bit later on. Seeing this though is a bit overwhelming, so perhaps the GNU dissambler via `objdump` will give us more information, it'll isolate just the executable data segment or the ".text" section, lets try that.

```x86asm
c.exe:     file format pei-x86-64


Disassembly of section .text:

0000000140001000 <__mingw_invalidParameterHandler>:
   140001000:   c3                      ret
   140001001:   66 66 2e 0f 1f 84 00    data16 cs nopw 0x0(%rax,%rax,1)
   140001008:   00 00 00 00
   14000100c:   0f 1f 40 00             nopl   0x0(%rax)

(~2000 lines more)
0000000140002988 <__DTOR_LIST__>:
   140002988:   ff                      (bad)
   140002989:   ff                      (bad)
   14000298a:   ff                      (bad)
   14000298b:   ff                      (bad)
   14000298c:   ff                      (bad)
   14000298d:   ff                      (bad)
   14000298e:   ff                      (bad)
   14000298f:   ff 00                   incl   (%rax)
   140002991:   00 00                   add    %al,(%rax)
   140002993:   00 00                   add    %al,(%rax)
   140002995:   00 00                   add    %al,(%rax)
        ...
```

Well, I guess that's a little better, and a little worse at the same time. So now we can see the explicit inclusion of the C runtime and Standard Library.  Theres a lot of C procedures that come straight from the C standard library (like `malloc` and `free`). Seems like there's a lot of unnecessary instructions in our executable for what we're trying to do. How can we make this better?

# Assembly

Well, theres only one thing to do. Not use a language. No matter what language we use, analyzing the binary would really just be analyzing the *Runtime*, after all, "Hello World" is unbelievably simple. Compared to the runtime code, its next to nothing.

Instead we're going to use assembly, which is barely considered a language, some people call it human readable machine code, but I actually think macroassemblers do a lot for you these days, and almost ressemble high level languages at this point. 

I specifically chose to use flat assembler, because of Mr. Zozin (tsoding), otherwise, chances were I was either going to use the GNU assembler, or the Netwide Assembler. FASM (flat assembler) doesn't require a linker, because it produces executables, which actually simplifies things.

While we could use Handles in Windows, which are similar to file descriptors in Unix, by using `GetStdHandle` and `WriteFile` from `kernel32.dll`, we could be lazy and just use `msvcrt.dll` which is the Microsoft C runtime library, which has a `printf`. It also makes our binary smaller. That's what I did because I'm lazy.

Another thing I didn't think about until after I finished doing everything is that the `.data` and `.text` sections could actually be combined, because we're only reading from the `.data` section not writing, therefore it can be in the readable executable segment. Unforunately however, data cannot be both writable and executable, because apparently that's not allowed on modern OS's. W^X (write xor execute) Data can only be writable or executable but not both. Apparently JIT compilers are able to get around this somehow, I'll have to look into how one day.

This is also a 32 bit executable instead of a 64 bit executable, for no real reason, but intel and windows are both backwards compatible so it doesn't matter that my machine is 64 bit.

As you'll eventually see, the assembly code maatches almost 1 to 1 with the machine code, which is why I'm not going to go over it too much detail, because that would spoil everything.

```x86asm
; /b.s
format PE                           ; Win32 portable executable 
entry _start                                 ; _start is the program's entry point

include '%FASMINC%/win32a.inc'  

section '.text' code readable executable     ; code

_start:
        invoke printf, stringformat, hello   ; call printf, defined in msvcrt.dll                      
        invoke ExitProcess, 0                ; exit the process
section '.data' data readable
        hello db "Hello World!", 0
        stringformat db "%s", 0ah, 0
section '.idata' import data readable      ; data imports

library kernel, 'kernel32.dll',\             ; link to kernel32.dll, msvcrt.dll
        msvcrt, 'msvcrt.dll'

import kernel, \                             ; import ExitProcess from kernel32.dll
       ExitProcess, 'ExitProcess'

import msvcrt, \                             ; import printf from msvcrt.dll
       printf, 'printf'
```
```
gg $fasm b.s && ./b
flat assembler  version 1.73.32  (1048576 kilobytes memory)
3 passes, 2048 bytes.
Hello World!
```
All this program does is print "Hello World!" to `stdout` and then exit with 0. That's no different then what the rest of our programs were doing, except... well, look at the dissassembly.

```x86asm
b.exe:     file format pei-i386


Disassembly of section .text:

00401000 <.text>:
  401000:       68 00 20 40 00          push   $0x402000
  401005:       68 0d 20 40 00          push   $0x40200d
  40100a:       ff 15 80 30 40 00       call   *0x403080
  401010:       6a 00                   push   $0x0
  401012:       ff 15 60 30 40 00       call   *0x403060
```
The dissassembly is almost nothing. You may have also noticed that the size of the entire executable is only 2048 bytes or 2 ^ 11 bytes or 2 KB. Thats more than 25 times smaller then the compiled C program! All `invoke` does is push the arguments for the procedure onto the stack in reverse order and then call it. Its a macro defined within `win32a.inc`. We can see the instructions after macro expansion in the dissassembly.

Now that we have a really small binary, it probably makes sense to just use a hex editor, beause otherwise trying to make sense of any of this is going to be way harder then it needs to be. I used **ImHex** while I did this, but I'll just be highlighting portions of the hexdumped code in this article.

# The PE Format

## DosHeader and DosStub

The first 128 bytes of a PE consist of the **DosHeader** and **DosStub**.

```
00000000  4d 5a 80 00 01 00 00 00  04 00 10 00 ff ff 00 00  |MZ..............|----|
00000010  40 01 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |@.......@.......|    |
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|    | DosHeader
00000030  00 00 00 00 00 00 00 00  00 00 00 00 80 00 00 00  |................|----|

00000040  0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |........!..L.!Th|----|
00000050  69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f  |is program canno|    |
00000060  74 20 62 65 20 72 75 6e  20 69 6e 20 44 4f 53 20  |t be run in DOS |    | DosStub
00000070  6d 6f 64 65 2e 0d 0a 24  00 00 00 00 00 00 00 00  |mode...$........|----|
```
The original **DosHeader** struct for the Windows API can be found in [*"winnt.h"*](https://github.com/wine-mirror/wine/blob/master/include/winnt.h). Wine has its own headerfile containing everything for the Windows API, and its the one I referenced.

I've redefined most of the original prototypes from the original headerfiles since I'm using Odin, but they're all identical. 

```odin
// DOS .EXE header
ImageDosHeader :: struct {
	e_magic:    u16, // Magic number
	e_cblp:     u16, // Bytes on last page of file
	e_cp:       u16, // Pages in file
	e_crlc:     u16, // Relocations
	e_cparhdr:  u16, // Size of header in paragraphs
	e_minalloc: u16, // Minimum extra paragraphs needed
	e_maxalloc: u16, // Maximum extra paragraphs needed
	e_ss:       u16, // Initial (relative) SS value
	e_sp:       u16, // Initial SP value
	e_csum:     u16, // Checksum
	e_ip:       u16, // Initial IP value
	e_cs:       u16, // Initial (relative) CS value
	e_lfarlc:   u16, // File address of relocation table
	e_ovno:     u16, // Overlay number
	e_res:      [4]u16, // Reserved words
	e_oemid:    u16, // OEM identifier (for e_oeminfo)
	e_oeminfo:  u16, // OEM information e_oemid specific
	e_res2:     [10]u16, // Reserved words
	e_lfanew:   u32, // File address of new exe header
}

DOS_HEADER :: [64]u8 {
77,90,128,0,1,0,0,0,
4,0,16,0,255,255,0,0,
64,1,0,0,0,0,0,0,
64,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,
0,0,0,0,128,0,0,0,
}
```
Since I don't actually care about this data, I'm just making it a constant. The first two bytes `4d 5a` or `77` and `90` are the magic number. The magic number when converted to ascii is `"MZ"`. Apparently these two bytes are actually the intials of a Microsoft Engineer named "Mark Zbikowski", who was one of the lead developers responsible for MS-DOS.  This signature is used by the MS-DOS 16 bit executable format, and is included here for backwards compaitibility.

The only other number that matters here, is 128, this is little endian, so the last unsigned 32 bit integer of the struct starts with the 128 byte as the first byte. 128 is just the offset from the start of the `DosHeader` to the `NTHeaders`, which makes sense because the `DosHeader` and `DosStub` together are 128 bytes.

So, literally for my program, I just create a buffer or dynamic array of bytes, and append to it, that's it.

```odin
	bin: [dynamic]byte //Binary buffer
	dos_header := DOS_HEADER
        append(&bin, ..dos_header[:])
```
```
00000040  0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |........!..L.!Th|----|
00000050  69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f  |is program canno|    |
00000060  74 20 62 65 20 72 75 6e  20 69 6e 20 44 4f 53 20  |t be run in DOS |    | DosStub
00000070  6d 6f 64 65 2e 0d 0a 24  00 00 00 00 00 00 00 00  |mode...$........|----|
```
```odin
DOS_STUB :: [64]u8 {
14,31,186,14,0,180,9,205,
33,184,1,76,205,33,84,104,
105,115,32,112,114,111,103,114,
97,109,32,99,97,110,110,111,
116,32,98,101,32,114,117,110,
32,105,110,32,68,79,83,32,
109,111,100,101,46,13,10,36,
0,0,0,0,0,0,0,0,
}
```
Next is the `DosStub`, which is just a small MS-DOS executable that prints the message, as plainly seen, "This program cannot be run in DOS Mode." There are other resources that go into exactly what the `DosStub` does, while looking at its dissassembly, but I really don't care because this portion of the executable only exists for historical reasons. The only reason the `DosHeader` and `DosStub` exists is because of backwards compatability. Its to ensure that if for some god forsaken reason you try to run a 32 bit or 64 bit PE on a 16 bit MS-DOS machine, it will at the very least have predictable behavior, print a message and exit.

So, the next thing I did was just append these bytes to the buffer aswell.

```odin
dos_stub := DOS_STUB
append(&bin, ..dos_stub[:])
```

## NT Headers

Next is the `IMAGE_NT_HEADERS`, again I redefined it in Odin, but the original version exists in a headerfile. There's two versions of the `IMAGE_NT_HEADERS` one for 32 bit executables and one for 64 bit executables called `IMAGE_NT_HEADERS64`. Since I'm creating a 32 bit executable, I used the former.

```odin
ImageNtHeaders :: struct {
	Signature:      u32,
	FileHeader:     ImageFileHeader,
	OptionalHeader: ImageOptionalHeader32,
}

PE_SIGNATURE :: [4]byte{0x50, 0x45, 0, 0}
```
The signature is just 4 bytes that when converted to ascii are "PE\0\0". I also just made these 4 bytes a constant and appended them to my buffer. It might be annoying that I've just hardcoded most of the bytes up until this point, almost as if I'm cheating, but that ends after this, I promise.

```odin
pe_signature := PE_SIGNATURE
append(&bin, ..pe_signature[:])
```
```odin
ImageFileHeader :: struct {
	Architecture:         ArchitectureType,
	NumberOfSections:     u16,
	TimeDateStamp:        u32,
	PointerToSymbolTable: u32,
	NumberOfSymbols:      u32,
	SizeOfOptionalHeader: u16,
	Characteristics:      u16,
}

ArchitectureType :: enum u16 {
	Unknown       = 0x00,
	ALPHAAXPOld   = 0x183,
	ALPHAAXP      = 0x184,
	ALPHAAXP64Bit = 0x284,
	AM33          = 0x1D3,
	AMD64         = 0x8664,
	ARM           = 0x1C0,
	ARM64         = 0xAA64,
	ARMNT         = 0x1C4,
	CLRPureMSIL   = 0xC0EE,
	EBC           = 0xEBC,
	I386          = 0x14C,
	I860          = 0x14D,
	IA64          = 0x200,
	LOONGARCH32   = 0x6232,
	LOONGARCH64   = 0x6264,
	M32R          = 0x9041,
	MIPS16        = 0x266,
	MIPSFPU       = 0x366,
	MIPSFPU16     = 0x466,
	MOTOROLA68000 = 0x268,
	POWERPC       = 0x1F0,
	POWERPCFP     = 0x1F1,
	POWERPC64     = 0x1F2,
	R3000         = 0x162,
	R4000         = 0x166,
	R10000        = 0x168,
	RISCV32       = 0x5032,
	RISCV64       = 0x5064,
	RISCV128      = 0x5128,
	SH3           = 0x1A2,
	SH3DSP        = 0x1A3,
	SH4           = 0x1A6,
	SH5           = 0x1A8,
	THUMB         = 0x1C2,
	WCEMIPSV2     = 0x169,
}
```
## File Header

Next is the `ImageFileHeader` sometimes referred to as the COFF Header. My definition is only slightly different than *winnt.h* I use `Architecture` and `ArchichectureType` instead of `Machine` and my constants for each `Machine` or `Architecture` are defined inside of an enum, while in *winnt.h* they're defined as standalone constants. Its only different because I pulled the definitions from ImHex, but they mean the same thing.

```
00000080  50 45 00 00 4c 01 03 00  f8 6e 78 67 00 00 00 00  |PE..L....nxg....|
00000090  00 00 00 00 e0 00 0f 01                           |................|
```

To create the bytes of this portion of the PE, all I did was write a procedure that returns the `ImageFileHeader`, if we add all of the bytes in the struct we get a size of 20. If we add the bytes from the signature, and the `ImageFileHeader` it would equal exactly 24 bytes.

Since we're creating a 32 bit executable, the architecture is `i386`, which is the intel 32 bit architecture. If we were creating a 64 bit executable for intel, then the architecture would be `AMD64`.

If we look back to our assembly code, we can see that we have exactly 3 sections. `'.text'`, `'.data'`, and `'.idata'`. So thats the number we provide for the number of sections. 

Depending on the language there might be different ways of obtaining the `TimeDateStamp`, what worked for me in Odin was simply taking the nanoseconds from the current time, which is a signed 64 bit integer, then deviding that by 1,000,000,000, and then casting it to a `u32` (unsigned 32 bit integer). That gives us a unix timestamp of when the file was created. The `PointerToSymbolTable` and `NumberOfSymbols` are both values of 0 because COFF debugging information is deprecated. 

```odin
ImageOptionalHeader32 :: struct {
	//
	// Standard fields.
	//
	Magic:                       PEFormat,
	MajorLinkerVersion:          u8,
	MinorLinkerVersion:          u8,
	SizeOfCode:                  u32,
	SizeOfInitializedData:       u32,
	SizeOfUninitializedData:     u32,
	AddressOfEntryPoint:         u32,
	BaseOfCode:                  u32,
	BaseOfData:                  u32,

	//
	// NT additional fields.
	//
	ImageBase:                   u32,
	SectionAlignment:            u32,
	FileAlignment:               u32,
	MajorOperatingSystemVersion: u16,
	MinorOperatingSystemVersion: u16,
	MajorImageVersion:           u16,
	MinorImageVersion:           u16,
	MajorSubsystemVersion:       u16,
	MinorSubsystemVersion:       u16,
	Win32VersionValue:           u32,
	SizeOfImage:                 u32,
	SizeOfHeaders:               u32,
	CheckSum:                    u32,
	Subsystem:                   SubsystemType,
	DllCharacteristics:          u16,
	SizeOfStackReserve:          u32,
	SizeOfStackCommit:           u32,
	SizeOfHeapReserve:           u32,
	SizeOfHeapCommit:            u32,
	LoaderFlags:                 u32,
	NumberOfRvaAndSizes:         u32,
	Directories:                 [16]DataDirectory,
}
```

Then we provide the size of the `ImageOptionalHeader` which is the last field in the NT headers. Depending on wether the executable is 64 bits or 32 bits, the size of the Optional Header will be different. For 32 bit executables the size is 0xE0 (224). For 64 bit executables the size would be 0xF0 (240). If we add all of the bytes in `ImageOptionalHeader32`, we do get a value of 224.

```odin
create_image_file_header :: proc() -> ImageFileHeader {
        stamp: u32 = u32(time.now()._nsec / 1_000_000_000)
 
	return ImageFileHeader {
		Architecture = ArchitectureType.I386,
		NumberOfSections = 3,
		TimeDateStamp = stamp,
		SizeOfOptionalHeader = 0xE0, // 0xE0 for 32bit, 0xF0 for 64bit
		Characteristics = getImageCharacteristics(),
	}
}
```
The last field of information for the `ImageFileHeader` resides within the `Characteristics`. Which are a group of flags indicating the attributes for the file, like wether the file is an executable or a DLL, or wether its for a 32 bit machine or a 64 bit machine. Flags are just powers of 2, since a bit is just a power of 2, where each bit in the `Characteristics` refers to an attribute. Using binary **OR(|)**, we can combine all of the relevant flags which are defined as a set of constants, and get the correct `Charactersitics` for our executable.

These are a description of the flags which I pulled from [Microsoft's official Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

IMAGE_FILE_RELOCS_STRIPPED
	0x0001
	Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files. 

IMAGE_FILE_EXECUTABLE_IMAGE
	0x0002
	Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error. 

IMAGE_FILE_32BIT_MACHINE
	0x0100
	Machine is based on a 32-bit-word architecture. 

```odin
getImageCharacteristics :: proc() -> u16 {
	return IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
}
```

## Optional Header

Next is the `ImageOptionalHeader` and its anything but optional. Infact its the most important part of the NT headers. It will of course be different for 32 bit and 64 bit executables. Below is my redefined version of the `ImageOptionalHeader` for 32 bit executables.

```odin
ImageOptionalHeader32 :: struct {
	//
	// Standard fields.
	//
	Magic:                       PEFormat,
	MajorLinkerVersion:          u8,
	MinorLinkerVersion:          u8,
	SizeOfCode:                  u32,
	SizeOfInitializedData:       u32,
	SizeOfUninitializedData:     u32,
	AddressOfEntryPoint:         u32,
	BaseOfCode:                  u32,
	BaseOfData:                  u32,

	//
	// NT additional fields.
	//
	ImageBase:                   u32,
	SectionAlignment:            u32,
	FileAlignment:               u32,
	MajorOperatingSystemVersion: u16,
	MinorOperatingSystemVersion: u16,
	MajorImageVersion:           u16,
	MinorImageVersion:           u16,
	MajorSubsystemVersion:       u16,
	MinorSubsystemVersion:       u16,
	Win32VersionValue:           u32,
	SizeOfImage:                 u32,
	SizeOfHeaders:               u32,
	CheckSum:                    u32,
	Subsystem:                   SubsystemType,
	DllCharacteristics:          u16,
	SizeOfStackReserve:          u32,
	SizeOfStackCommit:           u32,
	SizeOfHeapReserve:           u32,
	SizeOfHeapCommit:            u32,
	LoaderFlags:                 u32,
	NumberOfRvaAndSizes:         u32,
	Directories:                 [16]DataDirectory,
}
```
The magic number or the `Magic` field just indicates wether the format of the file is a 32 bit PE or a 64 bit PE (PE32Plus), or a ROM. 

Obviously, we want `PE32`, because we're creating a 32 bit executable. The values are stored in an enum called `PEFormat`.

I didn't set the linker versions because we're not using a linker, since we're manually creating the PE. But normally the major and minor linker version would be set for whatever linker is being used.

The size of the code section which contains our executable data (.text) and the initilized data section (.data) which contains the read only data containing "Hello World" are both 512, the reason being is that the minimum file alignment on Windows is typically 512 bytes, so the smallest a section can be is 512, since our entire file has to be aligned to 512 bytes. [The Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) explicitly state that the file alignment should be a number between 512 and 64K inclusive, and that the default is 512.

We have no uninitilized data, so the size is not set.

The address of the entry point is dependant upon the RVAs of the sections. The value of `AddressOfEntryPoint` would be equal to the RVA of the `'.text'` section or executable segment in addition to the offset of the entry point label. If the section was first, then it would 0x1000 +  whataver offset, if it was second it would be 0x2000 + whatever offset, depends on how the sections are ordered. In our case, since the `'.text'` section is second, the RVA of our code section is 0x2000 , and since we have no offset, the entry point is at the very beggining of the `'.text'` section, or more specifically the entry point address is 0x2000, or 8192 in decimal notation. The reason its 0x2000, is because of the section alignment of 0x1000, which we'll get to in the future.

The base of the code will be the same as the address of the entry point in this case, however, if the entry point did not start at the base of the code, then they would be different. The base of the code is equal to the RVA of the `.text` section or executable segment, 0x2000 in this case, since the `'.text'` section is second.

The base of the data is will be RVA of the `'.data'` section, which is 0x1000 in our case, since its the first section. This field is only present in 32 bit executables.

The `ImageBase` is the first byte of the image when loaded into memory, since the default for Windows NT is 0x00400000, that's what we're providing, this is in [Microsoft's Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

As we've already briefly mentioned, the section alignment is 0x1000, this is because that is the default and smallest memory page size for Windows on most processors, actually 4096 or 4KB to be exact, but same value. This is also stated in [Microsofts Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). This means that sections can be mapped into memory without having to make any adjustments.

We've already discussed file alignment, another thing of note, is that if the section alignment is less than the page size, then the file alignmenet and section alignment values have to match.

I couldnt't find any good resources for what the major and minor Os Versions should be, nor the subsystem versions, nor the image versions, so I just copied the values from an existing executable without much thought.

The `Win32VersionValue` value can be ignored, since it should be set to 0 as per the [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

The `SizeOfImage` has to be a multiple of the section alignment, and its also rounded up, so that value for us would be 0x4000.

The `SizeOfHeaders` is the combined size of the Dos header, signature, Image file header, optional header, and all section headers, and rounded up to a multiple of the `FileAlignment` also stated in [Microsofts Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). This of course gives us a value of 512.

The `Checksum` value is important for drivers and DLLs loaded into a critical system process as stated in [Microsoft's Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), however this value doesn't seem to matter much for userspace programs, and didn't affect the result of the executable, therefore I didn't set it.

The `Subsystem` value is 3, but is defined in an enum called `SubsystemType`, these values were taken from ImHex aswell, the hex editor I'm using, and it represents `WindowsCUI`, which is stated in [Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) to mean "Windows character-mode user interface (CUI) subsystem." Basically its for console applications; which our "Hello World" program qualifies as.

We have no DLL characteristics, so I provided none. The name is actually a result of backwards compatibility, because the field was originally created for DLLs in mind, but at this point the `DLLCharacteristics` are used for regular executables aswell.

I could not find any information on what the stack and heap, commit and reserve should be, so I gave them the values I found in the assembly program I assembled. I set the `StackCommit` and `StackReserve` to 0x1000, and the `HeapReserve` to 0x10000, and left the `HeapCommit` set to 0. I believe the reason for reserving and committing 0x1000 bytes of stack memory is because that is the page size. I don't have much of an idea concerning the Heap.

The `LoaderFlags` field is obsolete according to [Microsoft's Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), and should be set to 0.

16 is the number of `DataDirectory` entries, which is the value that `NumberOfRvaAndSizes` is set to, 16 is the most common value for most PE's, but its also the max number of data directories that can exist in a PE.

The only directory we actually care about for this executable is the import directory. Which is index 1 in the `DataDirectory` entries, and is defined as a contant (`IMAGE_DIRECTORY_ENTRY_IMPORT`). We set the RVA to 0x3000, because thats where our `'.idata`' or import section lies since its the third section. The virtual size of the `'.idata'` section is 146 so we set the `Size` field to that value, this information is actually repeated later on. That concludes the `ImageOptionalHeader` and the `ImageNTHeaders`.

```odin
create_optional_header :: proc() -> ImageOptionalHeader32 {
	dd: [16]DataDirectory
	dd[IMAGE_DIRECTORY_ENTRY_IMPORT].RVA = 0x3000
	dd[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 146

	return ImageOptionalHeader32 {
		Magic = PEFormat.PE32,
		SizeOfCode = 512,
		SizeOfInitializedData = 512,
		AddressOfEntryPoint = 0x2000,
		BaseOfCode = 0x2000,
		BaseOfData = 0x1000,
		ImageBase = 0x00400000,
		SectionAlignment = 0x1000,
		FileAlignment = 512,
		MajorOperatingSystemVersion = 1,
		MajorSubsystemVersion = 3,
		MinorSubsystemVersion = 10,
		SizeOfImage = 0x4000,
		SizeOfHeaders = 512,
		Subsystem = SubsystemType.WindowsCUI,
		SizeOfStackReserve = 0x1000,
		SizeOfStackCommit = 0x1000,
		SizeOfHeapReserve = 0x10000,
		NumberOfRvaAndSizes = 16,
		Directories = dd,
	}
}
```
As always we just append these bytes to the buffer.

```odin
	image_header_struct := create_image_file_header()
	image_header := mem.ptr_to_bytes(&image_header_struct)
	optional_header_struct := create_optional_header()
	optional_header := mem.ptr_to_bytes(&optional_header_struct)
   	append(&bin, ..image_header)
	append(&bin, ..optional_header)
```

# Section Headers

```odin
ImageSectionHeader :: struct {
	Name:                 [8]u8,
	VirtualSize:          u32,
	VirtualAddress:       u32,
	SizeOfRawData:        u32,
	PointerToRawData:     u32,
	PointerToRelocations: u32,
	PointerToLinenumbers: u32,
	NumberOfRelocations:  u16,
	NumberOfLinenumbers:  u16,
	Characteristics:      u32,
}
```

After the `ImageOptionalHeader` comes the Section Headers, also known as the Section Table, which contain a lot of relevant information for each of the sections in the executable. The sections are the part of the executable that actually contain data, both executable and other data used in the program.

After the section headers, the sections themselves occupy the rest of the PE file. In other words, we are almost done. The first field in a `ImageSectionHeader` is the section name or `Name`. 

Section names can be anything 8 bytes or less, and they're stored within the section header as an array of 8 bytes padded with 0s for any unused characters. Section names can technically be anything, but there are certain names that mean something by convention, a list of these names can be found in [Microsoft's official Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). 

The `VirtualSize`, is just the size of the actual data occupying the section, without the added padding, it describes the total size of the section when loaded into memory. 

For instance, the `'.data'` section contains the strings `"Hello World!"`, and `"%s\n"`, both ending in a byte of 0 for null termination, and if you add the total number of bytes, 12 + 1 + 3 + 1, you get the total number of bytes occupied by the data, which is of course 17. The same logic can be used for the other sections.  

We've come across the virtual addresses before to some extent. The `'.data'` section of course has a virtual address of 0x1000, which is the address of the first byte in the section relative to the image base address, this will make much more sense later. Then of course theres the `'.text'` section which is second and has a virtual address of 0x2000. The third section `'.idata'` has a virtual address of 0x3000, following this same pattern. If we had more sections I'm sure you could figure out their virtual addresses aswell.

Next is the `SizeOfRawData` which is equivalent to the total number of bytes occupied by the section including the padding. This is the size of the section within the actual file, when stored on disk. Since our sections are aligned (rounded up to) the value of our `FileAlignment` which is 512, the actual size of each of our sections (on disk) is 512, since that is the minimum space they can occupy to statisfy alignment requirements. The actual data is padded with zeroes to reach 512 bytes.

The `PointerToRawData` will be equivalent to the sum of all `SizeOfRawData` fields for all sections before the current section, including the current section, it is essentially a calculated offset taking into account the position of the section. The first section's header has a `PointerToRawData` value that is equal to its `SizeOfRawData`. Each subsequent section header will have a `PointerToRawData` value that increases by 512, because thats the size of every section.

The `PointerToRelocations` is set to 0 for executables. The `PointerToLineNumbers` field is also 0 because COFF debugging information is deprecated. `NumberOfRelocations` is also 0 for executables.`NumberOfLinenumbers` is set to 0 once again because COFF debugging information is deprecated. All of these details are stated in [Microsoft's Official Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). Since 0 is the default value in Odin, we can leave these values unset. 

The most interesting part of the section headers is perhaps the `Characteristics`, and they are also, in many ways, the most important part of the section headers, because they specify the type of data in the section. The `Characteristics` field on the `ImageSectionHeader` are similar to the `Characteristics` found in a different portion of the executable. They are a group of flags describing the section.

```odin
create_section_headers :: proc() -> [dynamic]ImageSectionHeader {
	return [dynamic]ImageSectionHeader {
		{
			Name             = [8]u8{0x2E, 0x64, 0x61, 0x74, 0x61, 0, 0, 0}, // .data
			VirtualSize      = 17,
			VirtualAddress   = 0x1000,
			SizeOfRawData    = 512,
			PointerToRawData = 512,
			Characteristics  = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
		},
		{
			Name             = [8]u8{0x2E, 0x74, 0x65, 0x78, 0x74, 0, 0, 0}, //.text
			VirtualSize      = 24,
			VirtualAddress   = 0x2000,
			SizeOfRawData    = 512,
			PointerToRawData = 1024,
			Characteristics  = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE,
		},
		{
			Name             = [8]u8{0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0, 0}, // .idata
			VirtualSize      = 146,
			VirtualAddress   = 0x3000,
			SizeOfRawData    = 512,
			PointerToRawData = 1536,
			Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
		},
	}
}
```
These are actually very easy to see in the assembly itself. By specifying wether a section is `data readable` we are setting flags in the section header. By labeling the section with `data` we are saying that this section contains initialized data, which is the flag `IMAGE_SCN_CNT_INITIALIZED_DATA`, by using the keyword `readable` we are saying this section is readable data, which sets the flag `IMAGE_SCN_MEM_READ`. We can of course use binary OR **(|)** to combine these flags and get a final unsigned 32 bit value containing all of the flags. This is the same for the rest of the sections. The `Characteristics` are what actually matter for a section in a PE, they describe how the data of a section can be accessed once loaded into memory, the section names are basically just for convention. The complete list for all section characteristics can of course be found in [Microsoft's Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

```x86asm
format PE                           ; Win32 portable executable 
entry _start                                 ; _start is the program's entry point

include '%FASMINC%/win32a.inc'  

section '.data' data readable
        hello db "Hello World!", 0
        stringformat db "%s", 0ah, 0

section '.text' code readable executable     ; code
_start:
        invoke printf, stringformat, hello   ; call printf, defined in msvcrt.dll                      
        invoke ExitProcess, 0                ; exit the process

section '.idata' import data readable      ; data imports

library kernel, 'kernel32.dll',\             ; link to kernel32.dll, msvcrt.dll
        msvcrt, 'msvcrt.dll'

import kernel, \                             ; import ExitProcess from kernel32.dll
       ExitProcess, 'ExitProcess'

import msvcrt, \                             ; import printf from msvcrt.dll
       printf, 'printf'
```

As stated in a different blog post that I read `SizeOfRawData` and `VirtualSize` can be, and are often different.

`SizeOfRawData` must be a multiple of the `FileAlignment` as stated earlier, so if the section size is less than that value, the rest gets padded with 0s and `SizeOfRawData` gets rounded up to the a multiple of the `FileAlignment`.

However when the section is loaded into memory it doesn’t follow that alignment and only the actual size of the section is occupied. This is the case in our executable since our section sizes are small. In this case, as we've seen, `SizeOfRawData` will be greater than the `VirtualSize`.

The opposite can happen as well. If the section contains uninitialized data, the data won’t be accounted for on disk, but when the section gets mapped into memory, the section will expand to reserve memory space for when the uninitialized data gets initialized and used later on. This would mean that the section on disk would occupy less than it would in memory, in this case `VirtualSize` will be greater than `SizeOfRawData`.

```odin
	section_headers := create_section_headers()
	section_header_bytes := dyn_array_to_bytes(section_headers)
	pad: [16]byte
   dyn_array_to_bytes :: proc(arr: [dynamic]$T) -> []byte {
      buf: [dynamic]byte
      for _, i in arr {
         b := mem.ptr_to_bytes(&arr[i])
         append(&buf, ..b)
      }
      return buf[:]
   }
   append(&bin, ..section_header_bytes)
	append(&bin, ..mem.ptr_to_bytes(&pad))
```

Once we have the section headers, which are 40 bytes each, we can just append them like we have everything else. We do have to add 16 bytes of padding at the end, the reason being that the section table or section headers are equal to 40 x 3 bytes which is 120 bytes. The `DosHeader`, `DosStub`, `NTHeaders` and section headers are a combined size of 496 bytes, which is 16 bytes off of the `FileAlignment`, since 496 + 16 = 512, the 16 bytes of padding solves our problem, and keeps everything aligned.

# Sections

## Data Section

We can finally get to the actual sections, which are the actual code in our program. Its kind of crazy that it took this long to get here, but here we are. Everything from this point on matches basically 1 to 1 with the assembly code.

Our first section was the `'.data'` section, containing the initialized data with two values, `"Hello World!"` and `"%s\n"` for the format string. As already stated, this entire section is only 17 bytes, its literally just the two pieces of data next to eachother. Hello World! is 12 characters, and with the addition of the null terminator its 13 bytes, the format string is 3 bytes, but 4 bytes with the null terminator, so together, the two pieces of data are 13 + 4 bytes or 17 bytes. However, the section as a whole has to be padded to stay aligned with the `FileAlignment`. 

```odin
create_data_section :: proc() -> []byte {
	buf: [dynamic]byte

	append(&buf, ..transmute([]u8)string("Hello World!"))
	append(&buf, 0)
	append(&buf, ..transmute([]u8)string("%s\n"))
	append(&buf, 0)

	inject_at_elem(&buf, 511, 0)
	return buf[:]
}
```

This is literally all the code necessary for creating this section. Create a buffer, append the bytes of the two strings with the null terminators into the buffer, then using `inject_at_elem` we can add a 0 value at index 511, which will expand the buffer to a length of 512 bytes, which is exactly what we need. Then we just return the slice at the end.

## The Executable Section

This next section is far more complicated then the last one. This is the executable section or the `'.text'` section, its where all of the actual instructions, and code for the program are located.

Understanding this portion of the executable requires understanding the Intel instruction set, so the [Intel Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) was referenced.

```x86asm
section '.text' code readable executable     ; code

_start:
        invoke printf, stringformat, hello   ; call printf, defined in msvcrt.dll                      
        invoke ExitProcess, 0                ; exit the process
```

If we look at our `'.text'` we see that we are using the `invoke` macro, and then passing 3 arguments `printf`, `stringformat`, and `hello`, and then we use `invoke` once more with two arguments being `ExitProcess` and `0`.

As mentioned before, all `invoke` does is push the arguments for the procedure onto the stack in reverse order and then call it. We can see the macro expansion if use a dissassembler, or if we just look at the machine code.

```x86asm
b.exe:     file format pei-i386


Disassembly of section .text:

00401000 <.text>:
  401000:       68 00 20 40 00          push   $0x402000
  401005:       68 0d 20 40 00          push   $0x40200d
  40100a:       ff 15 80 30 40 00       call   *0x403080
  401010:       6a 00                   push   $0x0
  401012:       ff 15 60 30 40 00       call   *0x403060
```

In Volume 2B Chapter 4, page 520 of the Intel Manual, we can see that opcode for pushing an immediate 32bit value is 0x68. I should also mention that since we're creating a 32bit executable, this is technically making use of Intels compatibility/Legacy mode.

Also we're seeing little endian in action here, the hex values are opposite to the way the value are arranged in the machine code.

Heres a markdown table to make things clearer. I also think it'll be useful to reference.

## PUSH Instruction Encoding Table

| Opcode   | Op/En | 64-Bit Mode | Compat/Leg Mode | Description              |
|----------|-------|-------------|-----------------|--------------------------|
| `FF /6`  | M     | Valid       | Valid           | Push `r/m16`.           |
| `FF /6`  | M     | N.E.        | Valid           | Push `r/m32`.           |
| `FF /6`  | M     | Valid       | N.E.            | Push `r/m64`.           |
| `50+rw`  | O     | Valid       | Valid           | Push `r16`.             |
| `50+rd`  | O     | N.E.        | Valid           | Push `r32`.             |
| `50+rd`  | O     | Valid       | N.E.            | Push `r64`.             |
| `6A ib`  | I     | Valid       | Valid           | Push `imm8`.            |
| `68 iw`  | I     | Valid       | Valid           | Push `imm16`.           |
| `68 id`  | I     | Valid       | Valid           | Push `imm32`.           |
| `0E`     | ZO    | Invalid     | Valid           | Push `CS`.              |
| `16`     | ZO    | Invalid     | Valid           | Push `SS`.              |
| `1E`     | ZO    | Invalid     | Valid           | Push `DS`.              |
| `06`     | ZO    | Invalid     | Valid           | Push `ES`.              |
| `0F A0`  | ZO    | Valid       | Valid           | Push `FS`.              |
| `0F A8`  | ZO    | Valid       | Valid           | Push `GS`.              |

### Legend
- **Op/En**: Operand encoding type.
- **64-Bit Mode**: Whether the instruction is valid in 64-bit mode.
- **Compat/Leg Mode**: Whether the instruction is valid in compatibility or legacy mode.
- **Description**: The operation performed by the instruction.
- **N.E.**: Not Encoded.

Since we're using 32bit assembly, all memory addresses will be 32bit, so in order to push the addresses of each of our strings we have to push what is essentially 2 32bit integers onto the stack. 

Then we're doing an indirect call on a 32 bit memory address for a procedure. The opcode for a `CALL` would be `0xFF`, and `/2` specifies the modrm byte used for an indirect call on a 32bit register. This is all listed in Volume 2A Chapter 3 page 139 of the Intel Manual.

Heres another table.

## CALL—Call Procedure
### Instruction Operand Encoding

| Opcode          | Instruction     | Op/En | 64-bit Mode | Compat/Leg Mode | Description                                                                                                                                 |
|------------------|-----------------|-------|-------------|-----------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `E8 cw`         | CALL rel16      | D     | N.S.        | Valid           | Call near, relative, displacement relative to the next instruction.                                                                        |
| `E8 cd`         | CALL rel32      | D     | Valid       | Valid           | Call near, relative, displacement relative to the next instruction. 32-bit displacement sign-extended to 64 bits in 64-bit mode.          |
| `FF /2`         | CALL r/m16      | M     | N.E.        | Valid           | Call near, absolute indirect, address given in `r/m16`.                                                                                   |
| `FF /2`         | CALL r/m32      | M     | N.E.        | Valid           | Call near, absolute indirect, address given in `r/m32`.                                                                                   |
| `FF /2`         | CALL r/m64      | M     | Valid       | N.E.            | Call near, absolute indirect, address given in `r/m64`.                                                                                   |
| `9A cd`         | CALL ptr16:16   | D     | Invalid     | Valid           | Call far, absolute, address given in operand.                                                                                             |
| `9A cp`         | CALL ptr16:32   | D     | Invalid     | Valid           | Call far, absolute, address given in operand.                                                                                             |
| `FF /3`         | CALL m16:16     | M     | Valid       | Valid           | Call far, absolute indirect, address given in `m16:16`.                                                                                   |
| `FF /3`         | CALL m16:32     | M     | Valid       | Valid           | In 32-bit mode: If selector points to a gate, RIP = 32-bit zero-extended displacement from gate; else RIP = zero-extended 16-bit offset.   |
| `FF /3`         | CALL m16:32     | M     | Valid       | Valid           | In 64-bit mode: If selector points to a gate, RIP = 64-bit displacement from gate; else RIP = zero-extended 32-bit offset.                |
| `REX.W FF /3`   | CALL m16:64     | M     | Valid       | N.E.            | In 64-bit mode: If selector points to a gate, RIP = 64-bit displacement from gate; else RIP = 64-bit offset.                              |

### Legend
- **Op/En**: Operand encoding type:
  - **D**: Direct operand (e.g., relative displacement or pointer).
  - **M**: Memory operand.
- **N.S.**: Not supported.
- **N.E.**: Not encoded.
- **RIP**: Instruction pointer register (64-bit mode).


So the ModRM byte has different meaning for all of the bit positions.

## ModR/M Byte Structure

| **Bit**   | **7**   | **6**   | **5**   | **4**   | **3**   | **2**   | **1**   | **0**   |
|-----------|---------|---------|---------|---------|---------|---------|---------|---------|
| **Usage** | Mod     | Mod     | Reg/Opcode | Reg/Opcode | Reg/Opcode | R/M     | R/M     | R/M     |


The Mod bits, which are bits 7 and 6 are used to specify the addressing mode, unless the values are `11`, in which case the Mod bits would actually be used to encode a register, if the values are anything else, they specify an addressing mode. `01` and `10` describe addressing with different displacements, while `00`, which is the value we'll use, describes a memory address with no displacement.

If the Mod bits specified an addressing mode, that means the r/m bits (bits 2-0) later on will be used to specify the adressing further. If the Mod bits are `00`, and the r/m bits are `101`, (like in our case) then this signifies a direct memory address. The instruction would then expect a 32 bit memory address to follow after the ModRM byte.

The `/2` corresponds to the `010` value for the Reg/Opcode bits or bits 5 - 3.

The value you get, when all of these bits are set in a byte, is `0x15`.

`FF 15` are the bytes that allow us make call on a procedure with a 32bit memory address.

The last push is an opcode for pushing a single byte value, or an 8 bit immediate value. In the Intel Manual the opcode for that is `0x6A`.

When `ExitProcess` is called the single byte argument is zero extended to a 32 bit value during execution.

That explains all of the opcodes, next lets talk about the image base, which we briefly mentioned earlier.

The default image base for an executable is 0x400000. The image base is the preferred starting address in memory where an executable or dynamic link library (DLL) is loaded.

All relative virtual addresses, will be relative to the image base. Which is why when we calculate the relative virtual address for our data in the `'.data'` section we add the image base and the RVA of the `'.data'` section, this gives us the RVA of the first byte in the `'.data'` section which points to our first string of `"Hello World!"`. 

To get the address of our format string we add 13 to the previous address, because thats the size of `"Hello World!"` including the null byte.

Theres only one group of variables left, and that is the two imported functions, `printf_iat` and `exit_iat`. 

The import section or `'.idata'` has a RVA of 0x3000, because its the third section, which is why our RVAs for these functions have a value that is more than 0x3000. 

When we look at the import table or import section, we can see that the executable section directly references the IAT RVAs (Import Address Table Relative Virtual Addresses). These RVAs act as placeholders for the actual memory addresses of the imported functions. 

At runtime, when the program is loaded into memory, the Windows loader resolves these placeholders by overwriting the IAT entries with the actual addresses of the functions. However, in the on-disk representation, the IAT entries still contain their original placeholder RVAs.

If only one imported function exists in a given DLL (like our case), the IAT RVA of the entire address table (from the Import Directory Table) will be the same as the IAT RVA of the first (and only) imported function. So that's why the IAT entries have the same RVA as the entire address table. Hopefully this makes more sense when we look at the `'.idata'` section more closely.

Once we have all of the numeric values for our executable data, we can kind of treat this like assembly. Where we append the bytes in the right order to get the final machine code.

First, we use the push32 opcode to push the 32-bit address of the "Hello World!" string onto the stack. Next, we push the 32-bit address of the format string. Then, we use the call opcode to call the IAT entry corresponding to the printf function. After displaying the message, we push an 8-bit value of 0 onto the stack using the push8 opcode and call the IAT entry for the exit function. Finally, as with all the other sections, we pad the buffer to 512 bytes by injecting at index 511.
```odin
create_exec_section :: proc() -> []byte {
	buf: [dynamic]byte

	//opcodes
	push32: byte : 0x68
	push8: byte : 0x6A
	call: byte : 0xFF
	modrm: byte : 0x15

	// Image Base
	image_base: u32 = 0x400000

	// RVAs of .data section
	data_rva: u32 = 0x1000 // Start of .data section
	hello_addr: u32 = image_base + data_rva // VA of "Hello World!"
	string_format_addr: u32 = hello_addr + 13 // VA of "%s\n"

	// imported functions
	printf_iat: u32 = image_base + 0x3080
	exit_iat: u32 = image_base + 0x3060
|
	append(&buf, push32)
	append(&buf, ..mem.ptr_to_bytes(&hello_addr))

	append(&buf, push32)
	append(&buf, ..mem.ptr_to_bytes(&string_format_addr))

	append(&buf, call, modrm)
	append(&buf, ..mem.ptr_to_bytes(&printf_iat))

	append(&buf, push8, 0)
	append(&buf, call, modrm)
	append(&buf, ..mem.ptr_to_bytes(&exit_iat))

	inject_at_elem(&buf, 511, 0)
	return buf[:]
}
```

## Import Section

Last but not least, is the import table. This is the last section of our executable, the `'.idata'` section.

The padding in this section is going to be confusing unless you realize that entire import table has to be aligned to a 4 byte boundary on 32 bit systems, which we're adhering to since we're creating a 32 bit executable, so just keep that in mind.
```odin
ImageImportDescriptor :: struct {
	OriginalFirstThunk: u32,
	TimeDateStamp:      u32,
	ForwarderChain:     u32,
	Name:               u32,
	FirstThunk:         u32,
}
```

 We start by defining the RVAs of everything we're going to need in the import table. The import table starts with the Import Directory Table, which is just an array of `IMAGE_IMPORT_DESCRIPTOR` structures, which I redefined in my Odin project as `ImageImportDescriptor`. Since the Import Directory Table doesn't have a fixed size, it has a null descriptor marking the end, similar to how null terminated strings have a null byte marking the end.

Each `ImageImportDescriptor` contains the following key fields (the only ones we care about anyways):

    OriginalFirstThunk:
        This is the RVA of the Import Lookup Table (ILT), which is also referred to as the Import Name Table (INT).
        The ILT contains entries that point to the names of the imported functions.

    Name:
        This is the RVA of the null-terminated string that specifies the name of the DLL (e.g., kernel32.dll or msvcrt.dll).

    FirstThunk:
        This is the RVA of the Import Address Table (IAT), where the Windows loader will write the resolved addresses of the imported functions at runtime.
        Initially, the IAT contains placeholders identical to the ILT.

In this example, we have two imported DLLs: `kernel32.dll` and `msvcrt.dll`. Therefore, the `ImageImportDescriptor` array has two entries (one for each DLL) followed by a null descriptor.

The `kernel32_name` and `msvcrt_name` are the RVAs of the null terminated string of the two imported dlls, which are `kernel32.dll` and `msvcrt.dll`. The `kernel32_thunk` and `msvcrt_thunk` are the RVAs of the ILT for each dll. The `kernel32_iat` and `msvcrt_iat` are the RVAs of the IAT for each dll.

Next are the `exit_hint`, and `print_hint` values. These are the RVAs of the Hint/Name Table entries for `ExitProcess` and `printf`. These values are exactly 8 bytes ahead of the corresponding address table entries. `empty_hint` is just a 16 bit value of 0.

With these values defined, we can construct the Import Directory Table by creating an array of `ImageImportDescriptor` structures, setting the correct values for each field.

After we append the bytes for the `imports_directory_table`,  we append the bytes for the `kernel32.dll` name. The string has 12 characters plus a null terminator, totaling 13 bytes. To align it to a 4-byte boundary, we add 1 byte of padding, bringing the total to 14 bytes.  We do the same with the `msvcrt.dll`. The string has 10 characters plus a null terminator, totaling 11 bytes. To align it to a 4-byte boundary, we add 3 bytes of padding, bringing the total to 14 bytes. The two DLL names together are a length of 28 bytes, which is 4 bytes aligned.

Then we append bytes for the RVA of the hint for the `ExitProcess` function (`exit_hint`) as the first entry in the ILT for the `kernel32.dll` Lookup Table. We then add a null terminator for the Lookup Table which is 4 bytes of 0 marking the end of the table.

We repeat this process for the IAT or (Import Address Table) for the `kernel32.dll`. We append the same RVA (`exit_hint`) as in the ILT. These are already aligned to a 4 byte boundary, so no padding needed.

If we had more imported functions for a DLL, then we would have more entries in both the Lookup Table and Address Table, but because we only have one entry per table, the null terminator might seem a bit out of place.

Next we append the bytes for the `ExitProcess` function name, which is prepended by an empty hint of 16 bits with a value of 0. The length of the characters in `ExitProcess` is 11, with the null terminator its 12, and with the 2 bytes from the empty hint, it is altogether 14 bytes, to align to a 4 byte boundary 2 bytes of padding are needed.

We literally just repeat the exact same process with the `printf` function and the `msvcrt.dll` DLL, and then we pad the buffer 512 bytes, and we are finished.
```odin
create_idata_sections :: proc() -> []byte {
	buf: [dynamic]byte

	// RVAs (Virtual Adresses)
	kernel32_name: u32 = 0x303C
	msvcrt_name: u32 = 0x304A
	kernel32_thunk: u32 = 0x3058
	msvcrt_thunk: u32 = 0x3078
	kernel32_iat: u32 = 0x3060
	msvcrt_iat: u32 = 0x3080
	exit_hint: u32 = 0x3068
	print_hint: u32 = 0x3088
	empty_hint: u16 = 0

	imports_directory_table := [3]ImageImportDescriptor {
		{OriginalFirstThunk = kernel32_thunk, Name = kernel32_name, FirstThunk = kernel32_iat},
		{OriginalFirstThunk = msvcrt_thunk, Name = msvcrt_name, FirstThunk = msvcrt_iat},
		{}, // null descriptor
	}

	append(&buf, ..mem.ptr_to_bytes(&imports_directory_table))
	append(&buf, ..transmute([]u8)string("kernel32.dll"))
	append(&buf, 0, 0) // extra byte for alignment
	append(&buf, ..transmute([]u8)string("msvcrt.dll"))
	append(&buf, 0, 0, 0, 0) // null terminator + 3 bytes for alignment

	// Lookup Table (OriginalFirstThunk)
	append(&buf, ..mem.ptr_to_bytes(&exit_hint)) // RVA for ExitProcess
	append(&buf, 0, 0, 0, 0) // null terminator

	// Address Table (FirstThunk)
	append(&buf, ..mem.ptr_to_bytes(&exit_hint)) // Same as Lookup Table initially
	append(&buf, 0, 0, 0, 0) // null terminator

	// Import Name Table (Hint/Name)
	append(&buf, ..mem.ptr_to_bytes(&empty_hint))
	append(&buf, ..transmute([]u8)string("ExitProcess"))
	append(&buf, 0) // Null terminator
	append(&buf, 0, 0) // Padding for alignment

	// Lookup Table (OriginalFirstThunk)
	append(&buf, ..mem.ptr_to_bytes(&print_hint)) // RVA for ExitProcess
	append(&buf, 0, 0, 0, 0) // null terminator

	// Address Table (FirstThunk)
	append(&buf, ..mem.ptr_to_bytes(&print_hint)) // Same as Lookup Table initially
	append(&buf, 0, 0, 0, 0) // null terminator

	// Import Name Table (Hint/Name)
	append(&buf, ..mem.ptr_to_bytes(&empty_hint))
	append(&buf, ..transmute([]u8)string("printf"))
	append(&buf, 0) // Null terminator
	append(&buf, 0, 0, 0) // Padding for alignment

	inject_at_elem(&buf, 511, 0)
	return buf[:]
}
```

We append all of the bytes for all of the section into a single buffer. and then we append all of those bytes to the end of our entire binary buffer.
```odin
create_sections :: proc() -> []byte {
	buf: [dynamic]byte
	append(&buf, ..create_data_section())
	append(&buf, ..create_exec_section())
	append(&buf, ..create_idata_sections())
	return buf[:]
}
```

```odin
   sections := create_sections()
	append(&bin, ..sections)
```

# Wrapping Up

This is the entirety of the main procedure, and it pretty much explains what we've done.
```odin
main :: proc() {
	bin: [dynamic]byte //Binary buffer

	// Produce all bytes
	dos_header := DOS_HEADER
	dos_stub := DOS_STUB
	pe_signature := PE_SIGNATURE
	image_header := create_image_file_header()
	optional_header := create_optional_header()
	section_headers := create_section_headers()
	section_header_bytes := dyn_array_to_bytes(section_headers)
	pad: [16]byte
	sections := create_sections()

	// Combine all bytes
	append(&bin, ..dos_header[:])
	append(&bin, ..dos_stub[:])
	append(&bin, ..pe_signature[:])
	append(&bin, ..mem.ptr_to_bytes(&image_header))
	append(&bin, ..mem.ptr_to_bytes(&optional_header))
	append(&bin, ..section_header_bytes)
	append(&bin, ..mem.ptr_to_bytes(&pad))
	append(&bin, ..sections)

	//Write bytes to file
	os.write_entire_file("bin.exe", bin[:])
}
```

Once we've written these bytes to a file, that file is a valid executable that can be run on a Windows machine.
```bash
$odin run . && ./bin
Hello World!
```
This was a fun project that taught me quite a bit, hopefully you learned something too.

# References
<https://github.com/wine-mirror/wine/blob/master/include/winnt.h>
<https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
<https://0xrick.github.io/win-internals/pe2/>
<https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>