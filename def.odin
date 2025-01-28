package main

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
	77,
	90,
	128,
	0,
	1,
	0,
	0,
	0,
	4,
	0,
	16,
	0,
	255,
	255,
	0,
	0,
	64,
	1,
	0,
	0,
	0,
	0,
	0,
	0,
	64,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	128,
	0,
	0,
	0,
}

DOS_STUB :: [64]u8 {
	14,
	31,
	186,
	14,
	0,
	180,
	9,
	205,
	33,
	184,
	1,
	76,
	205,
	33,
	84,
	104,
	105,
	115,
	32,
	112,
	114,
	111,
	103,
	114,
	97,
	109,
	32,
	99,
	97,
	110,
	110,
	111,
	116,
	32,
	98,
	101,
	32,
	114,
	117,
	110,
	32,
	105,
	110,
	32,
	68,
	79,
	83,
	32,
	109,
	111,
	100,
	101,
	46,
	13,
	10,
	36,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
}

PE_SIGNATURE :: [4]byte{0x50, 0x45, 0, 0}

ImageNtHeaders :: struct {
	Signature:      u32,
	FileHeader:     ImageFileHeader,
	OptionalHeader: ImageOptionalHeader32,
}

ImageFileHeader :: struct {
	Architecture:         ArchitectureType,
	NumberOfSections:     u16,
	TimeDateStamp:        u32,
	PointerToSymbolTable: u32,
	NumberOfSymbols:      u32,
	SizeOfOptionalHeader: u16,
	Characteristics:      u16,
}

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

DataDirectory :: struct {
	RVA:  u32,
	Size: u32,
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

/* These defines describe the meanings of the bits in the Characteristics
   field */

IMAGE_FILE_RELOCS_STRIPPED :: 0x0001 /* No relocation info */
IMAGE_FILE_EXECUTABLE_IMAGE :: 0x0002
IMAGE_FILE_LINE_NUMS_STRIPPED :: 0x0004
IMAGE_FILE_LOCAL_SYMS_STRIPPED :: 0x0008
IMAGE_FILE_AGGRESIVE_WS_TRIM :: 0x0010
IMAGE_FILE_LARGE_ADDRESS_AWARE :: 0x0020
IMAGE_FILE_16BIT_MACHINE :: 0x0040
IMAGE_FILE_BYTES_REVERSED_LO :: 0x0080
IMAGE_FILE_32BIT_MACHINE :: 0x0100
IMAGE_FILE_DEBUG_STRIPPED :: 0x0200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP :: 0x0400
IMAGE_FILE_NET_RUN_FROM_SWAP :: 0x0800
IMAGE_FILE_SYSTEM :: 0x1000
IMAGE_FILE_DLL :: 0x2000
IMAGE_FILE_UP_SYSTEM_ONLY :: 0x4000
IMAGE_FILE_BYTES_REVERSED_HI :: 0x8000

SubsystemType :: enum u16 {
	Unknown                = 0x00,
	Native                 = 0x01,
	WindowsGUI             = 0x02,
	WindowsCUI             = 0x03,
	OS2CUI                 = 0x05,
	POSIXCUI               = 0x07,
	Windows9xNative        = 0x08,
	WindowsCEGUI           = 0x09,
	EFIApplication         = 0x0A,
	EFIBootServiceDriver   = 0x0B,
	EFIRuntimeDriver       = 0x0C,
	EFIROM                 = 0x0D,
	Xbox                   = 0x0E,
	WindowsBootApplication = 0x10,
}

PEFormat :: enum u16 {
	ROM      = 0x107,
	PE32     = 0x10B,
	PE32Plus = 0x20B,
}

/* DLL Characteristics */
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA :: 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE :: 0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY :: 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT :: 0x0100
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION :: 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH :: 0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND :: 0x0800
IMAGE_DLLCHARACTERISTICS_APPCONTAINER :: 0x1000
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER :: 0x2000
IMAGE_DLLCHARACTERISTICS_GUARD_CF :: 0x4000
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE :: 0x8000

ImageOptionalHeader64 :: struct {
	Magic:                       u16, /* 0x20b */
	MajorLinkerVersion:          u8,
	MinorLinkerVersion:          u8,
	SizeOfCode:                  u32,
	SizeOfInitializedData:       u32,
	SizeOfUninitializedData:     u32,
	AddressOfEntryPoint:         u32,
	BaseOfCode:                  u32,
	ImageBase:                   u64,
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
	Subsystem:                   u16,
	DllCharacteristics:          u16,
	SizeOfStackReserve:          u64,
	SizeOfStackCommit:           u64,
	SizeOfHeapReserve:           u64,
	SizeOfHeapCommit:            u64,
	LoaderFlags:                 u32,
	NumberOfRvaAndSizes:         u32,
	DataDirectories:             [16]DataDirectory,
}

// Directory Entries

IMAGE_DIRECTORY_ENTRY_EXPORT :: 0 // Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT :: 1 // Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE :: 2 // Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION :: 3 // Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY :: 4 // Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC :: 5 // Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG :: 6 // Debug Directory
//IMAGE_DIRECTORY_ENTRY_COPYRIGHT    ::   7   // (X86 usage)
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE :: 7 // Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR :: 8 // RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS :: 9 // TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG :: 10 // Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT :: 11 // Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT :: 12 // Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT :: 13 // Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR :: 14 // COM Runtime descriptor

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

/* These defines are for the Characteristics bitfield. */

/* IMAGE_SCN_TYPE_REG		::	0x00000000 - Reserved */
/* IMAGE_SCN_TYPE_DSECT		::	0x00000001 - Reserved */
/* IMAGE_SCN_TYPE_NOLOAD	::	0x00000002 - Reserved */
/*  IMAGE_SCN_TYPE_GROUP	::		0x00000004 - Reserved */
IMAGE_SCN_TYPE_NO_PAD :: 0x00000008 /* Reserved */
/* IMAGE_SCN_TYPE_COPY	::		0x00000010 - Reserved */

IMAGE_SCN_CNT_CODE :: 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA :: 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA :: 0x00000080

IMAGE_SCN_LNK_OTHER :: 0x00000100
IMAGE_SCN_LNK_INFO :: 0x00000200
/* IMAGE_SCN_TYPE_OVER	::	0x00000400 - Reserved */
IMAGE_SCN_LNK_REMOVE :: 0x00000800
IMAGE_SCN_LNK_COMDAT :: 0x00001000

/* 						0x00002000 - Reserved */
/* IMAGE_SCN_MEM_PROTECTED 	::	0x00004000 - Obsolete */
IMAGE_SCN_MEM_FARDATA :: 0x00008000

/* IMAGE_SCN_MEM_SYSHEAP	::	0x00010000 - Obsolete */
IMAGE_SCN_MEM_PURGEABLE :: 0x00020000
IMAGE_SCN_MEM_16BIT :: 0x00020000
IMAGE_SCN_MEM_LOCKED :: 0x00040000
IMAGE_SCN_MEM_PRELOAD :: 0x00080000

IMAGE_SCN_ALIGN_1BYTES :: 0x00100000
IMAGE_SCN_ALIGN_2BYTES :: 0x00200000
IMAGE_SCN_ALIGN_4BYTES :: 0x00300000
IMAGE_SCN_ALIGN_8BYTES :: 0x00400000
IMAGE_SCN_ALIGN_16BYTES :: 0x00500000 /* Default */
IMAGE_SCN_ALIGN_32BYTES :: 0x00600000
IMAGE_SCN_ALIGN_64BYTES :: 0x00700000
IMAGE_SCN_ALIGN_128BYTES :: 0x00800000
IMAGE_SCN_ALIGN_256BYTES :: 0x00900000
IMAGE_SCN_ALIGN_512BYTES :: 0x00A00000
IMAGE_SCN_ALIGN_1024BYTES :: 0x00B00000
IMAGE_SCN_ALIGN_2048BYTES :: 0x00C00000
IMAGE_SCN_ALIGN_4096BYTES :: 0x00D00000
IMAGE_SCN_ALIGN_8192BYTES :: 0x00E00000
/* 						0x00F00000 - Unused */
IMAGE_SCN_ALIGN_MASK :: 0x00F00000

IMAGE_SCN_LNK_NRELOC_OVFL :: 0x01000000


IMAGE_SCN_MEM_DISCARDABLE :: 0x02000000
IMAGE_SCN_MEM_NOT_CACHED :: 0x04000000
IMAGE_SCN_MEM_NOT_PAGED :: 0x08000000
IMAGE_SCN_MEM_SHARED :: 0x10000000
IMAGE_SCN_MEM_EXECUTE :: 0x20000000
IMAGE_SCN_MEM_READ :: 0x40000000
IMAGE_SCN_MEM_WRITE :: 0x80000000

ImageImportDescriptor :: struct {
	OriginalFirstThunk: u32,
	TimeDateStamp:      u32,
	ForwarderChain:     u32,
	Name:               u32,
	FirstThunk:         u32,
}

ImageImportByName :: struct {
	Hint: u16,
	Name: []byte,
}
