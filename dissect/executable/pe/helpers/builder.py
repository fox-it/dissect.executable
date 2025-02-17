from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from dissect.executable.exception import BuildSectionException
from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.helpers import utils
from dissect.executable.pe.pe import PE

STUB = b"\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program is made with dissect.pe <3 kusjesvanSRT <3.\x0d\x0d\x0a$\x00\x00"  # noqa: E501


class Builder:
    """Base class for building the PE file with the user applied patches.

    Args:
        pe: A `PE` object.
        arch: The architecture to use for the new PE.
        dll: Whether the new PE should be a DLL or not.
        subsystem: The subsystem to use for the new PE default uses IMAGE_SUBSYSTEM_WINDOWS_GUI.
    """

    def __init__(
        self,
        arch: str = "x64",
        dll: bool = False,
        subsystem: int = 0x2,
    ):
        self.arch = (
            c_pe.MachineType.IMAGE_FILE_MACHINE_AMD64 if arch == "x64" else c_pe.MachineType.IMAGE_FILE_MACHINE_I386
        )
        self.dll = dll
        self.subsystem = subsystem

        self.pe = None

    def new(self) -> None:
        """Build the PE file from scratch.

        This function will build a new PE that consists of a single dummy section. It will not contain any imports,
        exports, code, etc.
        """

        new_pe = BytesIO()

        # Generate the MZ header
        self.mz_header = self.gen_mz_header()

        image_characteristics = self.get_characteristics()
        # Generate the file header
        self.file_header = self.gen_file_header(machine=self.arch, characteristics=image_characteristics)

        # Generate the optional header
        self.optional_header = self.gen_optional_header()

        # Add a dummy section header to the new PE, we need at least 1 section to parse the PE
        dummy_data = b"<3kusjesvanSRT<3"
        dummy_multiplier = 0x400 // len(b"<3kusjesvanSRT<3")

        section_header_offset = self.optional_header.SizeOfHeaders
        pointer_to_raw_data = utils.align_int(
            integer=section_header_offset + c_pe.IMAGE_SECTION_HEADER.size,
            blocksize=self.file_alignment,
        )
        dummy_section = self.section(
            pointer_to_raw_data=pointer_to_raw_data,
            virtual_address=self.optional_header.BaseOfCode,
            virtual_size=dummy_multiplier,
            raw_size=dummy_multiplier,
            characteristics=c_pe.SectionFlags.IMAGE_SCN_CNT_CODE
            | c_pe.SectionFlags.IMAGE_SCN_MEM_EXECUTE
            | c_pe.SectionFlags.IMAGE_SCN_MEM_READ
            | c_pe.SectionFlags.IMAGE_SCN_MEM_NOT_PAGED,
        )
        # Update the number of sections in the file header
        self.file_header.NumberOfSections += 1

        # Write the headers into the new PE
        new_pe.write(self.mz_header.dumps())
        new_pe.write(STUB)
        new_pe.seek(self.mz_header.e_lfanew)
        new_pe.write(b"PE\x00\x00")
        new_pe.write(self.file_header.dumps())
        new_pe.write(self.optional_header.dumps())

        # Write the dummy section header
        new_pe.write(dummy_section.dumps())

        # Write the data of the section
        new_pe.seek(dummy_section.PointerToRawData)
        new_pe.write(dummy_data * dummy_multiplier)

        self.pe = PE(pe_file=new_pe)

        # Fix our SizeOfImage field in the optional header
        self.pe.optional_header.SizeOfImage = self.pe_size

    def gen_mz_header(
        self,
        e_magic: int = 0x5A4D,
        e_cblp: int = 0,
        e_cp: int = 1,
        e_crlc: int = 0,
        e_cparhdr: int = 4,
        e_minalloc: int = 0,
        e_maxalloc: int = 0,
        e_ss: int = 0,
        e_sp: int = 0,
        e_csum: int = 0,
        e_ip: int = 0,
        e_cs: int = 0,
        e_lfarlc: int = 64,
        e_ovno: int = 0,
        e_res: list[int] | None = None,
        e_oemid: int = 0,
        e_oeminfo: int = 0,
        e_res2: list[int] | None = None,
        e_lfanew: int = 0,
    ) -> c_pe.IMAGE_DOS_HEADER:
        """Generate the MZ header for the new PE file.

        Args:
            e_magic: The magic number for the MZ header.
            e_cblp: The number of bytes on the last page of the file.
            e_cp: The number of pages in the file.
            e_crlc: The number of relocations.
            e_cparhdr: The number of paragraphs in the header.
            e_minalloc: The minimum number of paragraphs in the program.
            e_maxalloc: The maximum number of paragraphs in the program.
            e_ss: The relative value of the stack segment.
            e_sp: The initial value of the stack pointer.
            e_csum: The checksum.
            e_ip: The initial value of the instruction pointer.
            e_cs: The relative value of the code segment.
            e_lfarlc: The file address of the relocation table.
            e_ovno: The overlay number.
            e_res: The reserved words.
            e_oemid: The OEM identifier.
            e_oeminfo: The OEM information.
            e_res2: The reserved words.
            e_lfanew: The file address of the new exe header.

        Returns:
            The MZ header as a `cstruct` object.
        """

        mz_header = c_pe.IMAGE_DOS_HEADER()

        mz_header.e_magic = e_magic
        mz_header.e_cblp = e_cblp
        mz_header.e_cp = e_cp
        mz_header.e_crlc = e_crlc
        mz_header.e_cparhdr = e_cparhdr
        mz_header.e_minalloc = e_minalloc
        mz_header.e_maxalloc = e_maxalloc
        mz_header.e_ss = e_ss
        mz_header.e_sp = e_sp
        mz_header.e_csum = e_csum
        mz_header.e_ip = e_ip
        mz_header.e_cs = e_cs
        mz_header.e_lfarlc = e_lfarlc
        mz_header.e_ovno = e_ovno
        mz_header.e_res = e_res or [0, 0, 0, 0]
        mz_header.e_oemid = e_oemid
        mz_header.e_oeminfo = e_oeminfo
        mz_header.e_res2 = e_res2 or [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        # Calculate the start of the NT headers by checking the location and size of the relocation table
        # within the MZ header
        start_of_nt_header = (mz_header.e_lfarlc + (mz_header.e_crlc * 4)) + len(STUB)
        mz_header.e_lfanew = e_lfanew if e_lfanew else start_of_nt_header
        # Align the e_lfanew value
        mz_header.e_lfanew = mz_header.e_lfanew + (mz_header.e_lfanew % 2)

        return mz_header

    def get_characteristics(self) -> int:
        """Function to retreive the characteristics that are set based on the kind of PE file that needs to be
        generated.

        For now it will only contain the main characteristics of a PE file, like if it's an executable image and/or a
        DLL.

        Returns:
            The characteristics of the PE file.
        """

        output = c_pe.ImageCharacteristics.IMAGE_FILE_EXECUTABLE_IMAGE
        if self.arch != c_pe.MachineType.IMAGE_FILE_MACHINE_AMD64:
            output |= c_pe.ImageCharacteristics.IMAGE_FILE_32BIT_MACHINE

        if self.dll:
            output |= c_pe.ImageCharacteristics.IMAGE_FILE_DLL

        return output

    def gen_file_header(
        self,
        time_date_stamp: int = 0,
        pointer_to_symbol_table: int = 0,
        number_of_symbols: int = 0,
        size_of_optional_header: int = 0,
        characteristics: int = 0,
        machine: int = 0x8664,
        number_of_sections: int = 0,
    ) -> c_pe.IMAGE_FILE_HEADER:
        """Generate the file header for the new PE file.

        Args:
            time_date_stamp: The time and date the file was created.
            pointer_to_symbol_table: The file pointer to the COFF symbol table.
            number_of_symbols: The number of entries in the symbol table.
            size_of_optional_header: The size of the optional header.
            characteristics: The characteristics of the file.
            machine: The machine type.
            number_of_sections: The number of sections.

        Returns:
            The file header as a `cstruct` object.
        """

        # Set the size of the optional header if not given
        if not size_of_optional_header:
            if machine == 0x8664:
                size_of_optional_header = len(c_pe.IMAGE_OPTIONAL_HEADER64)
                self.machine = 0x8664
            else:
                size_of_optional_header = len(c_pe.IMAGE_OPTIONAL_HEADER)
                self.machine = 0x14C

        # Set the timestamp to now if not given
        if not time_date_stamp:
            time_date_stamp = int(datetime.now(tz=timezone.utc).timestamp())

        file_header = c_pe.IMAGE_FILE_HEADER()
        file_header.Machine = machine
        file_header.NumberOfSections = number_of_sections
        file_header.TimeDateStamp = time_date_stamp
        file_header.PointerToSymbolTable = pointer_to_symbol_table
        file_header.NumberOfSymbols = number_of_symbols
        file_header.SizeOfOptionalHeader = size_of_optional_header
        file_header.Characteristics = characteristics

        return file_header

    def gen_optional_header(
        self,
        magic: int = 0,
        major_linker_version: int = 0xE,
        minor_linker_version: int = 0,
        size_of_code: int = 0,
        size_of_initialized_data: int = 0,
        size_of_uninitialized_data: int = 0,
        address_of_entrypoint: int = 0,
        base_of_code: int = 0x1000,
        imagebase: int = 0x69000,
        section_alignment: int = 0x1000,
        file_alignment: int = 0x200,
        major_os_version: int = 0x5,
        minor_os_version: int = 0x2,
        major_image_version: int = 0,
        minor_image_version: int = 0,
        major_subsystem_version: int = 0x5,
        minor_subsystem_version: int = 0x2,
        win32_version_value: int = 0,
        size_of_image: int = 0,
        size_of_headers: int = 0x400,
        checksum: int = 0,
        subsystem: int = 0x2,
        dll_characteristics: int = 0,
        size_of_stack_reserve: int = 0x1000,
        size_of_stack_commit: int = 0x1000,
        size_of_heap_reserve: int = 0x1000,
        size_of_heap_commit: int = 0x1000,
        loaderflags: int = 0,
        number_of_rva_and_sizes: int = c_pe.IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
        datadirectory: list[c_pe.IMAGE_DATA_DIRECTORY] | None = None,
    ) -> c_pe.IMAGE_OPTIONAL_HEADER | c_pe.IMAGE_OPTIONAL_HEADER64:
        """Generate the optional header for the new PE file.

        Args:
            magic: The magic number for the optional header, this indicates the architecture for the PE.
            major_linker_version: The major version of the linker.
            minor_linker_version: The minor version of the linker.
            size_of_code: The size of the code section.
            size_of_initialized_data: The size of the initialized data section.
            size_of_uninitialized_data: The size of the uninitialized data section.
            address_of_entrypoint: The address of the entry point.
            base_of_code: The base of the code section.
            imagebase: The base address of the image.
            section_alignment: The alignment of sections in memory.
            file_alignment: The alignment of sections in the file.
            major_os_version: The major version of the operating system.
            minor_os_version: The minor version of the operating system.
            major_image_version: The major version of the image.
            minor_image_version: The minor version of the image.
            major_subsystem_version: The major version of the subsystem.
            minor_subsystem_version: The minor version of the subsystem.
            win32_version_value: The Win32 version value.
            size_of_image: The size of the image.
            size_of_headers: The size of the headers.
            checksum: The checksum of the image.
            subsystem: The subsystem of the image.
            dll_characteristics: The DLL characteristics of the image.
            size_of_stack_reserve: The size of the stack to reserve.
            size_of_stack_commit: The size of the stack to commit.
            size_of_heap_reserve: The size of the heap to reserve.
            size_of_heap_commit: The size of the heap to commit.
            loaderflags: The loader flags.
            number_of_rva_and_sizes: The number of RVA and sizes.
            datadirectory: The data directory entries, initialized as nullbyte directories.

        Returns:
            The optional header as a `cstruct` object.
        """

        if self.machine == 0x8664:
            optional_header = c_pe.IMAGE_OPTIONAL_HEADER64()
            _magic = 0x20B
        else:
            optional_header = c_pe.IMAGE_OPTIONAL_HEADER()
            _magic = 0x10B

        optional_header.Magic = magic or _magic
        self.file_alignment = file_alignment
        self.section_alignment = section_alignment

        # Calculate the SizeOfHeaders field, we add the length of a section header because we know there's going to be
        # at least 1 section header
        size_of_headers = utils.align_int(
            integer=len(self.mz_header)
            + len(STUB)
            + len(b"PE\x00\x00")
            + len(self.file_header)
            + len(optional_header)
            + len(c_pe.IMAGE_SECTION_HEADER),
            blocksize=file_alignment,
        )

        optional_header.MajorLinkerVersion = major_linker_version
        optional_header.MinorLinkerVersion = minor_linker_version
        optional_header.SizeOfCode = size_of_code
        optional_header.SizeOfInitializedData = size_of_initialized_data
        optional_header.SizeOfUninitializedData = size_of_uninitialized_data
        optional_header.AddressOfEntryPoint = address_of_entrypoint
        optional_header.BaseOfCode = base_of_code
        optional_header.ImageBase = imagebase
        optional_header.SectionAlignment = section_alignment
        optional_header.FileAlignment = file_alignment
        optional_header.MajorOperatingSystemVersion = major_os_version
        optional_header.MinorOperatingSystemVersion = minor_os_version
        optional_header.MajorImageVersion = major_image_version
        optional_header.MinorImageVersion = minor_image_version
        optional_header.MajorSubsystemVersion = major_subsystem_version
        optional_header.MinorSubsystemVersion = minor_subsystem_version
        optional_header.Win32VersionValue = win32_version_value
        optional_header.SizeOfImage = size_of_image
        optional_header.SizeOfHeaders = size_of_headers
        optional_header.CheckSum = checksum
        optional_header.Subsystem = subsystem
        optional_header.DllCharacteristics = dll_characteristics
        optional_header.SizeOfStackReserve = size_of_stack_reserve
        optional_header.SizeOfStackCommit = size_of_stack_commit
        optional_header.SizeOfHeapReserve = size_of_heap_reserve
        optional_header.SizeOfHeapCommit = size_of_heap_commit
        optional_header.LoaderFlags = loaderflags
        optional_header.NumberOfRvaAndSizes = number_of_rva_and_sizes
        optional_header.DataDirectory = datadirectory or [
            c_pe.IMAGE_DATA_DIRECTORY(BytesIO(b"\x00" * len(c_pe.IMAGE_DATA_DIRECTORY)))
            for _ in range(c_pe.IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        ]

        return optional_header

    def section(
        self,
        pointer_to_raw_data: int,
        name: str | bytes = b".dissect",
        virtual_size: int = 0x1000,
        virtual_address: int = 0x1000,
        raw_size: int = 0x200,
        pointer_to_relocations: int = 0,
        pointer_to_linenumbers: int = 0,
        number_of_relocations: int = 0,
        number_of_linenumbers: int = 0,
        characteristics: int = 0x68000020,
    ) -> c_pe.IMAGE_SECTION_HEADER:
        """Build a new section for the PE.

        The default characteristics of the new section will be:
            - IMAGE_SCN_CNT_CODE
            - IMAGE_SCN_MEM_EXECUTE
            - IMAGE_SCN_MEM_READ
            - IMAGE_SCN_MEM_NOT_PAGED

        Args:
            pointer_to_raw_data: The file pointer to the raw data of the new section.
            name: The new section name, default: .dissect
            virtual_size: The virtual size of the new section data.
            virtual_address: The virtual address where the new section is located.
            raw_size: The size of the section data.
            pointer_to_relocations: The file pointer to the relocation table.
            pointer_to_linenumbers: The file pointer to the line number table.
            number_of_relocations: The number of relocations.
            number_of_linenumbers: The number of line numbers.
            characteristics: The characteristics of the new section.

        Returns:
            The new section header as a `cstruct` object.
        """

        if len(name) > 8:
            raise BuildSectionException("section names can't be longer than 8 characters")

        if isinstance(name, str):
            name = name.encode()

        section_header = c_pe.IMAGE_SECTION_HEADER()

        pointer_to_raw_data = utils.align_int(integer=pointer_to_raw_data, blocksize=self.file_alignment)

        section_header.Name = name + utils.pad(size=8 - len(name))
        section_header.VirtualSize = virtual_size
        section_header.VirtualAddress = virtual_address
        section_header.SizeOfRawData = raw_size
        section_header.PointerToRawData = pointer_to_raw_data
        section_header.PointerToRelocations = pointer_to_relocations
        section_header.PointerToLinenumbers = pointer_to_linenumbers
        section_header.NumberOfRelocations = number_of_relocations
        section_header.NumberOfLinenumbers = number_of_linenumbers
        section_header.Characteristics = characteristics

        return section_header

    @property
    def pe_size(self) -> int:
        """Calculate the new PE size.

        We can calculate the new size of the PE by adding the virtual address and virtual size of the last section
        together.

        Returns:
            The size of the PE.
        """

        last_section = self.pe.patched_sections[next(reversed(self.pe.patched_sections))]
        va = last_section.virtual_address
        size = last_section.virtual_size

        return utils.align_int(integer=(va + size), blocksize=self.section_alignment)
