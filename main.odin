package main

import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:time"


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
	write_hex_bytes(bin)
}

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

create_image_file_header :: proc() -> ImageFileHeader {
	stamp: u32 = u32(time.now()._nsec / 1_000_000_000)
	chars := getImageCharacteristics()
	return ImageFileHeader {
		Architecture         = ArchitectureType.I386,
		NumberOfSections     = 3,
		TimeDateStamp        = stamp,
		SizeOfOptionalHeader = 0xE0, // 0xE0 for 32bit, 0xF0 for 64bit
		Characteristics      = chars,
	}
}

getImageCharacteristics :: proc() -> u16 {
	return IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
}

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

create_data_section :: proc() -> []byte {
	buf: [dynamic]byte

	append(&buf, ..transmute([]u8)string("Hello World!"))
	append(&buf, 0)
	append(&buf, ..transmute([]u8)string("%s\n"))
	append(&buf, 0)

	inject_at_elem(&buf, 511, 0)
	return buf[:]
}

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
	append(&buf, 0) // Padding for alignment

	inject_at_elem(&buf, 511, 0)
	return buf[:]
}

create_sections :: proc() -> []byte {
	buf: [dynamic]byte
	append(&buf, ..create_data_section())
	append(&buf, ..create_exec_section())
	append(&buf, ..create_idata_sections())
	return buf[:]
}

dyn_array_to_bytes :: proc(arr: [dynamic]$T) -> []byte {
	buf: [dynamic]byte
	for _, i in arr {
		b := mem.ptr_to_bytes(&arr[i])
		append(&buf, ..b)
	}
	return buf[:]
}

write_hex_bytes :: proc(bin: [dynamic]byte) {
	rbin: [dynamic]byte
	hexdata := hex.encode(bin[:])
	append(&rbin, ..hexdata)
	// Split into 32-byte chunks
	newbin: [dynamic]byte
	for i in 0 ..= (len(rbin) + 31) / 32 {
		start := i * 32
		end := start + 32
		if start >= len(rbin) {
			break // Stop the loop if start exceeds bin length
		}
		if end > len(rbin) {
			end = len(rbin)
		}
		append(&newbin, ..rbin[start:end])
		append(&newbin, 10)
	}

	// Write to file
	if os.exists("src.hex") {
		handle, err := os.open("src.hex", 0x01)
		if err != 0 {
			fmt.println(err)
		}
		os.write(handle, newbin[:])
	} else {
		os.write_entire_file("src.hex", newbin[:])
	}
}
