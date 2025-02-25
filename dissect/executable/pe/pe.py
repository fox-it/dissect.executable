from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.executable.exception import (
    InvalidAddress,
    InvalidArchitecture,
    InvalidPE,
    InvalidVA,
    ResourceException,
)
from dissect.executable.pe.c_pe import c_cv_info, c_pe
from dissect.executable.pe.helpers import (
    exports,
    imports,
    patcher,
    relocations,
    resources,
    sections,
    tls,
    utils,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cstruct.cstruct import cstruct
    from dissect.cstruct.types.enum import EnumInstance

    from dissect.executable.pe.helpers.resources import Resource


class PE:
    """Base class for parsing PE files.

    Args:
        pe_file: A file-like object of an executable.
        virtual: Indicate whether the PE file exists within a memory image.
        parse: Indicate if the different sections should be parsed automatically.
    """

    def __init__(self, pe_file: BinaryIO, virtual: bool = False):
        pe_file.seek(0)
        self.pe_file = BytesIO(pe_file.read())
        self.virtual = virtual

        # Make sure we reset any kind of pointers within the PE file before continueing
        self.pe_file.seek(0)

        self.mz_header = None
        self.file_header = None
        self.nt_headers = None
        self.optional_header = None

        self.section_header_offset = 0
        self.last_section_offset = 0

        self.sections: OrderedDict[str, sections.PESection] = OrderedDict()
        self.patched_sections: OrderedDict[str, sections.PESection] = OrderedDict()

        self.imports: OrderedDict[str, imports.ImportModule] = None
        self.exports: OrderedDict[str, exports.ExportFunction] = None
        self.resources: OrderedDict[str, resources.Resource] = None
        self.raw_resources = None
        self.relocations: list[dict] = None
        self.tls_callbacks = None

        self.directories = OrderedDict()

        # We always want to parse the DOS header and NT headers
        self.parse_headers()

        # The offset of the section header is always at the end of the NT headers
        self.section_header_offset = self.pe_file.tell()

        self.imagebase = self.optional_header.ImageBase
        self.file_alignment = self.optional_header.FileAlignment
        self.section_alignment = self.optional_header.SectionAlignment

        self.base_address = self.optional_header.ImageBase

        self.timestamp = datetime.fromtimestamp(self.file_header.TimeDateStamp, tz=timezone.utc)

        # Parse the section header
        self.parse_section_header()

        # Parsing the directories present in the PE
        self.parse_directories()

    def _valid(self) -> bool:
        """Check if the PE file is a valid PE file. By looking for the "PE" signature at the offset of e_lfanew.

        Returns:
            `True` if the file is a valid PE file, `False` otherwise.
        """

        self.pe_file.seek(self.mz_header.e_lfanew)
        return c_pe.uint32(self.pe_file) == 0x4550

    def is64bit(self) -> bool:
        return self.file_header.Machine == c_pe.MachineType.IMAGE_FILE_MACHINE_AMD64

    def parse_headers(self) -> None:
        """Function to parse the basic PE headers:
            - DOS header
            - File header (part of NT header)
            - Optional header (part of NT header)

        Function also sets some architecture dependent variables.

        Raises:
            InvalidPE if the PE file is not a valid PE file.
            InvalidArchitecture if the architecture is not supported or unknown.
        """

        self.mz_header = c_pe.IMAGE_DOS_HEADER(self.pe_file)

        if not self._valid():
            raise InvalidPE("file is not a valid PE file")

        self.file_header = c_pe.IMAGE_FILE_HEADER(self.pe_file)

        image_nt_headers_offset = self.mz_header.e_lfanew
        self.pe_file.seek(image_nt_headers_offset)

        # Set the architecture specific settings
        self._check_architecture()
        if self.file_header.Machine == c_pe.MachineType.IMAGE_FILE_MACHINE_AMD64:
            self.nt_headers = c_pe.IMAGE_NT_HEADERS64(self.pe_file)
        else:
            self.nt_headers = c_pe.IMAGE_NT_HEADERS(self.pe_file)

        self.optional_header = self.nt_headers.OptionalHeader

    def _check_architecture(self) -> None:
        """Check whether the architecture belonging to the binary is one we support.

        Raises:
            InvalidArchitecture if the architecture is not supported or unknown.
        """
        if self.file_header.Machine not in [
            c_pe.MachineType.IMAGE_FILE_MACHINE_AMD64,
            c_pe.MachineType.IMAGE_FILE_MACHINE_I386,
        ]:
            raise InvalidArchitecture(f"Invalid architecture found: {self.file_header.Machine:02x}")

    def parse_section_header(self) -> None:
        """Parse the sections within the PE file."""

        self.pe_file.seek(self.section_header_offset)

        for _ in range(self.file_header.NumberOfSections):
            # Keep track of the last section offset
            offset = self.pe_file.tell()
            section_header = c_pe.IMAGE_SECTION_HEADER(self.pe_file)
            section_name = section_header.Name.decode().strip("\x00")
            # Take note of the sections, keep track of any patches seperately
            self.sections[section_name] = sections.PESection(pe=self, section=section_header, offset=offset)
            self.patched_sections[section_name] = sections.PESection(pe=self, section=section_header, offset=offset)

        self.last_section_offset = self.sections[next(reversed(self.sections))].offset

    def section(self, va: int = 0, name: str = "") -> sections.PESection | None:
        """Function to retrieve a section based on the given virtual address or name.

        Args:
            va: The virtual address to look for within the sections.
            name: The name of the section.

        Returns:
            A `PESection` object.
        """

        if not name:
            for section in self.sections.values():
                if va in range(
                    section.virtual_address,
                    section.virtual_address + section.virtual_size,
                ):
                    return section
            return None
        return self.sections[name]

    def patched_section(self, va: int = 0, name: str = "") -> sections.PESection | None:
        """Function to retrieve a patched section based on the given virtual address or name.

        Args:
            va: The virtual address to look for within the patched sections.
            name: The name of the patched section.

        Returns:
            A `PESection` object.
        """

        if not name:
            for section in self.patched_sections.values():
                if va in range(
                    section.virtual_address,
                    section.virtual_address + section.virtual_size,
                ):
                    return section
            return None
        return self.patched_sections[name]

    def datadirectory_section(self, index: int) -> sections.PESection:
        """Return the section that contains the given virtual address.

        Args:
            index: The index of the data directory to find the associated section for.

        Returns:
            The section that contains the given virtual address.
        """

        va = self.directory_va(index=index)
        for section in self.patched_sections.values():
            if va >= section.virtual_address and va < section.virtual_address + section.virtual_size:
                return section

        raise InvalidVA(f"VA not found in sections: {va:#04x}")

    def parse_directories(self) -> None:
        """Parse the different data directories in the PE file and initialize their associated managers.

        For now the following data directories are implemented:
            - Import Address Table (IAT)
            - Export Directory
            - Resources
            - Base Relocations
            - Thread Local Storage (TLS) Callbacks
        """

        for idx in range(c_pe.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
            if not self.has_directory(index=idx):
                continue

            # Take note of the current directory VA so we can dynamically update it when resizing sections
            section = self.datadirectory_section(index=idx)
            directory_va_offset = self.optional_header.DataDirectory[idx].VirtualAddress - section.virtual_address
            section.directories[idx] = directory_va_offset

            # Parse the Import Address Table (IAT)
            if idx == c_pe.IMAGE_DIRECTORY_ENTRY_IMPORT:
                self.import_mgr = imports.ImportManager(pe=self, section=section)
                self.imports = self.import_mgr.imports

            if idx == c_pe.IMAGE_DIRECTORY_ENTRY_EXPORT:
                self.export_mgr = exports.ExportManager(pe=self, section=section)
                self.exports = self.export_mgr.exports

            # Parse the resources directory entry of the PE file
            if idx == c_pe.IMAGE_DIRECTORY_ENTRY_RESOURCE:
                self.rsrc_mgr = resources.ResourceManager(pe=self, section=section)
                self.resources = self.rsrc_mgr.resources
                self.raw_resources = self.rsrc_mgr.raw_resources

            # Parse the relocation directory entry of the PE file
            if idx == c_pe.IMAGE_DIRECTORY_ENTRY_BASERELOC:
                self.reloc_mgr = relocations.RelocationManager(pe=self, section=section)
                self.relocations = self.reloc_mgr.relocations

            # Parse the TLS directory entry of the PE file
            if idx == c_pe.IMAGE_DIRECTORY_ENTRY_TLS:
                self.tls_mgr = tls.TLSManager(pe=self, section=section)
                self.tls_callbacks = self.tls_mgr.callbacks

    def get_resource_type(self, rsrc_id: str | EnumInstance) -> Iterator[Resource]:
        """Yields a generator containing all of the nodes within the resources that contain the requested ID.

        The ID can be either given by name or its value.

        Args:
            rsrc_id: The resource ID to find, this can be a cstruct `EnumInstance` or `str`.

        Yields:
            All of the nodes that contain the requested type.
        """

        if rsrc_id not in self.resources:
            raise ResourceException(f"Resource with ID {rsrc_id} not found in PE!")

        yield from self.rsrc_mgr.parse_resources(resources=self.resources[rsrc_id])

    def virtual_address(self, address: int) -> int:
        """Return the virtual address given a (possible) physical address.

        Args:
            address: The address to translate.

        Returns:
            The virtual address as an` int`
        """

        if self.virtual:
            return address

        for section in self.patched_sections.values():
            max_address = section.virtual_address + section.virtual_size
            if address >= section.virtual_address and address < max_address:
                return section.pointer_to_raw_data + (address - section.virtual_address)

        raise InvalidVA(f"VA not found in sections: {address:#04x}")

    def raw_address(self, offset: int) -> int:
        """Return the physical address given a virtual address.

        Args:
            offset: The offset to translate into a virtual address.

        Returns:
            The physical address as an `int`.
        """

        for section in self.patched_sections.values():
            max_address = section.pointer_to_raw_data + section.size_of_raw_data
            if offset >= section.pointer_to_raw_data and offset < max_address:
                return section.virtual_address + (offset - section.pointer_to_raw_data)

        raise InvalidAddress(f"Raw address not found in sections: {offset:#04x}")

    def virtual_read(self, address: int, size: int) -> bytes:
        """Wrapper for reading virtual address offsets within a PE file.

        Args:
            address: The virtual address to read from.
            size: The amount of bytes to read from the given virtual address.

        Returns:
            The bytes that were read.
        """

        physical_address = self.virtual_address(address=address)
        if self.virtual:
            return self.pe_file.readoffset(offset=physical_address, size=size)

        self.pe_file.seek(physical_address)
        return self.pe_file.read(size)

    def raw_read(self, offset: int, size: int) -> bytes:
        """Read the amount of bytes denoted by the size argument within the PE file at the given offset.

        Args:
            offset: The offset within the file to start reading.
            size: The amount of bytes to read within the PE file.

        Returns:
            The bytes that were read from the given offset.
        """

        old_offset = self.pe_file.tell()
        self.pe_file.seek(offset)

        data = self.pe_file.read(size)
        self.pe_file.seek(old_offset)
        return data

    def seek(self, address: int) -> None:
        """Seek to the given virtual address within a PE file.

        Args:
            address: The virtual address to seek to.
        """

        raw_address = self.virtual_address(address=address)
        self.pe_file.seek(raw_address)

    def tell(self) -> int:
        """Returns the current offset within the PE file.

        Returns:
            The current offset within the PE file.
        """

        offset = self.pe_file.tell()
        return self.raw_address(offset=offset)

    def read(self, size: int) -> bytes:
        """Read x amount of bytes of the PE file.

        Args:
            size: The amount of bytes to read.

        Returns:
            The bytes that were read.
        """

        return self.pe_file.read(size)

    def write(self, data: bytes) -> None:
        """Write the data to the PE file.

        This write function will also make sure to update the section data.

        Args:
            data: The data to write to the PE file.
        """

        offset = self.tell()

        # Write the data to the PE file so we can do a raw_read on this data in the section
        self.pe_file.write(data)
        print(self.patched_sections)

        # Update the section data
        for section in self.patched_sections.values():
            if section.virtual_address <= offset and section.virtual_address + section.virtual_size >= offset:
                self.seek(address=section.virtual_address)
                section.data = self.read(size=section.virtual_size)

    def read_image_directory(self, index: int) -> bytes:
        """Read the PE file image directory entry of a given index.

        Args:
            index: The index of the data directory to read.

        Returns:
            The bytes of the directory that was read.
        """

        directory_entry = self.optional_header.DataDirectory[index]
        return self.virtual_read(address=directory_entry.VirtualAddress, size=directory_entry.Size)

    def directory_va(self, index: int) -> int:
        """Returns the virtual address of a directory given its index.

        Args:
            index: The index of the data directory to read.

        Returns:
            The virtual address of the data directory at the given index.
        """

        return self.optional_header.DataDirectory[index].VirtualAddress

    def has_directory(self, index: int) -> bool:
        """Check if a certain data directory exists within the PE file given its index.

        Args:
            index: The index of the data directory to check.

        Returns:
            `True` if the data directory has a size associated with it, indicating it exists, `False` otherwise.
        """

        return self.optional_header.DataDirectory[index].Size != 0

    def debug(self) -> cstruct | None:
        """Return the debug directory of the given PE file.

        Returns:
            A `cstruct` object of the debug entry within the PE file.
        """

        debug_directory_entry = self.read_image_directory(index=c_pe.IMAGE_DIRECTORY_ENTRY_DEBUG)
        image_directory_size = len(c_pe.IMAGE_DEBUG_DIRECTORY)

        for _ in range(len(debug_directory_entry) // image_directory_size):
            entry = c_pe.IMAGE_DEBUG_DIRECTORY(debug_directory_entry)
            dbg_entry = self.virtual_read(address=entry.AddressOfRawData, size=entry.SizeOfData)

            if entry.Type == 0x2:
                return c_cv_info.CV_INFO_PDB70(dbg_entry)
        return None

    def get_section(self, segment_index: int) -> tuple[str, sections.PESection]:
        """Retrieve the section of the PE by index.

        Args:
            segment_index: The segment to retrieve based on the order within the PE.

        Returns:
            A `tuple` contianing the section name and attributes as `PESection`.
        """

        sections = list(self.sections.items())

        idx = 0 if segment_index - 1 == -1 else segment_index
        section_name = sections[idx - 1][0]

        return self.sections[section_name]

    def symbol_data(self, symbol: cstruct, size: int) -> bytes:
        """Retrieve data from the PE using a PDB symbol.

        Args:
            symbol: A `cstruct` object of a symbol.
            size: The size to read from the symbol offset.

        Returns:
            The bytes that were read from the offset within the PE.
        """

        _section = self.get_section(segment_index=symbol.seg)
        address = self.imagebase + _section.virtual_address + symbol.off

        self.pe_file.seek(address)
        return self.pe_file.read(size)

    def add_section(
        self,
        name: str,
        data: bytes,
        va: int | None = None,
        datadirectory: int | None = None,
        datadirectory_rva: int | None = None,
        datadirectory_size: int | None = None,
        size: int | None = None,
    ) -> None:
        """Add a new section to the PE file.

        Args:
            name: The name of the new section.
            data: The data to add to the new section.
            datadirectory: Whether this section should be a specific data directory entry.
            rva: The RVA of the directory entry if this is different than the virtual address of the section.
            size: The size of the entry.
        """

        # Take note of the last section
        last_section = self.patched_sections[next(reversed(self.sections))]

        # Calculate the new section size
        raw_size = utils.align_int(integer=len(data), blocksize=self.file_alignment)
        virtual_size = size or len(data)

        # Use the provided RVA or calculate the new section virtual address

        virtual_address = va or utils.align_int(
            integer=last_section.virtual_address + last_section.virtual_size,
            blocksize=self.section_alignment,
        )

        # Calculate the new section raw address
        pointer_to_raw_data = last_section.pointer_to_raw_data + last_section.size_of_raw_data

        # Build the new section
        new_section = sections.build_section(
            virtual_size=virtual_size,
            virtual_address=virtual_address,
            raw_size=raw_size,
            pointer_to_raw_data=pointer_to_raw_data,
            name=name.encode(),
        )

        # Update the last section offset
        offset = last_section.offset + c_pe.IMAGE_SECTION_HEADER.size
        self.last_section_offset = offset

        # Increment the NumberOfSections field
        self.file_header.NumberOfSections += 1

        # Set the VA and size of the datadirectory entry if this was marked as being such
        if datadirectory is not None:
            self.optional_header.DataDirectory[datadirectory].VirtualAddress = datadirectory_rva or virtual_address
            self.optional_header.DataDirectory[datadirectory].Size = datadirectory_size or len(data)

        # Add the new section to the PE
        self.sections[name] = sections.PESection(pe=self, section=new_section, offset=offset, data=data)
        self.patched_sections[name] = sections.PESection(pe=self, section=new_section, offset=offset, data=data)

        # Update the SizeOfImage field
        last_section = self.patched_sections[next(reversed(self.patched_sections))]
        last_va = last_section.virtual_address
        last_size = last_section.virtual_size

        pe_size = utils.align_int(integer=(last_va + last_size), blocksize=self.section_alignment)
        self.optional_header.SizeOfImage = pe_size

        # Write the data to the PE file
        self.pe_file.seek(pointer_to_raw_data)
        if virtual_size > raw_size:
            data += utils.pad(virtual_size - raw_size)

        # Pad the data to align the section
        padsize = utils.align_int(integer=len(data), blocksize=self.section_alignment)
        data += utils.pad(size=padsize)
        self.pe_file.write(data)

        # Reparse the directories
        self.parse_directories()

    def write_pe(self, filename: str = "out.exe") -> None:
        """Write the contents of the PE to a new file.

        This will use the patcher that is part of the project to make sure any kind of relative addressing is also
        corrected for the supported data directories.

        Args:
            filename: The filename to write the PE to, default out.exe.
        """

        pepatcher = patcher.Patcher(pe=self)
        new_pe = pepatcher.build
        Path(filename).write_bytes(new_pe.read())
