from __future__ import annotations

import io
from bisect import bisect_right
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, BufferedStream, RangeStream
from dissect.util.ts import from_unix

from dissect.executable.exception import InvalidSignatureError
from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory import (
    BaseRelocationDirectory,
    BoundImportDirectory,
    ComDescriptorDirectory,
    DataDirectory,
    DebugDirectory,
    DelayImportDirectory,
    ExceptionDirectory,
    ExportDirectory,
    IatDirectory,
    ImportDirectory,
    LoadConfigDirectory,
    ResourceDirectory,
    SecurityDirectory,
    TlsDirectory,
)

if TYPE_CHECKING:
    import datetime


class PE:
    """PE file parser.

    Args:
        fh: A file-like object of an executable.
        virtual: Indicate whether to use virtual addressing instead of physical.
                 Use this when the file has already been mapped into memory.
    """

    def __init__(self, fh: BinaryIO, virtual: bool = False):
        self.fh = fh
        self.virtual = virtual

        self.fh.seek(0)

        self.mz_header = c_pe.IMAGE_DOS_HEADER(self.fh)
        if self.mz_header.e_magic != c_pe.IMAGE_DOS_SIGNATURE:
            raise InvalidSignatureError(
                f"File is not a valid PE file, wrong MZ signature: {self.mz_header.e_magic.to_bytes(2, 'little')} "
                f"(expected {c_pe.IMAGE_DOS_SIGNATURE.to_bytes(2, 'little')})"
            )

        self.os2_header = None
        self.file_header = None
        self.optional_header = None
        self.sections: list[Section] = []
        self.vfh = None

        self.fh.seek(self.mz_header.e_lfanew)
        signature = c_pe.ULONG(fh)
        if (signature & 0xFFFF) == c_pe.IMAGE_OS2_SIGNATURE:
            self.fh.seek(-4, io.SEEK_CUR)
            self.os2_header = c_pe.IMAGE_OS2_HEADER(self.fh)

        elif signature == c_pe.IMAGE_NT_SIGNATURE:
            # No need to correct the offset
            self.file_header = c_pe.IMAGE_FILE_HEADER(self.fh)

            if self.file_header.SizeOfOptionalHeader:
                optional_magic = c_pe.USHORT(self.fh)
                self.fh.seek(-2, io.SEEK_CUR)

                if optional_magic == c_pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                    self.optional_header = c_pe.IMAGE_OPTIONAL_HEADER32(self.fh)
                elif optional_magic == c_pe.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                    self.optional_header = c_pe.IMAGE_OPTIONAL_HEADER64(self.fh)
                else:
                    raise InvalidSignatureError(
                        f"File is not a valid PE file, wrong NT header magic: {optional_magic:#x} "
                        f"(expected {c_pe.IMAGE_NT_OPTIONAL_HDR32_MAGIC:#x} or {c_pe.IMAGE_NT_OPTIONAL_HDR64_MAGIC:#x})"
                    )

            self.sections = [Section.from_fh(self, self.fh) for _ in range(self.file_header.NumberOfSections)]

            self.vfh = self.open()
        else:
            raise InvalidSignatureError(
                f"File is not a valid PE file, wrong header signature: {signature.to_bytes(4, 'little')} "
                f"(expected {c_pe.IMAGE_NT_SIGNATURE.to_bytes(4, 'little')} (NT) "
                f"or {c_pe.IMAGE_OS2_SIGNATURE.to_bytes(2, 'little')} (OS/2))"
            )

        self.fh.seek(len(self.mz_header))
        self.dos_stub = self.fh.read(self.mz_header.e_lfanew - len(self.mz_header))

    @property
    def machine(self) -> c_pe.IMAGE_FILE_MACHINE:
        """Return the machine type of the PE file."""
        if not self.file_header:
            return c_pe.IMAGE_FILE_MACHINE.UNKNOWN
        return self.file_header.Machine

    @property
    def image_base(self) -> int:
        """Return the image base address of the PE file."""
        if not self.optional_header:
            return 0
        return self.optional_header.ImageBase

    @property
    def timestamp(self) -> datetime.datetime | None:
        """The compilation timestamp of the PE file, or ``None`` if the PE file is compiled as reproducible."""
        if not self.file_header or self.is_reproducible():
            return None
        return from_unix(self.file_header.TimeDateStamp)

    def is_pe(self) -> bool:
        """Return if the file is a valid PE file."""
        return self.is_nt()

    def is_nt(self) -> bool:
        """Return if the file is a valid NT executable."""
        return self.file_header is not None

    def is_os2(self) -> bool:
        """Return if the file is an OS/2 executable."""
        return self.os2_header is not None

    def is_64bit(self) -> bool:
        """Return if the PE file is 64-bit (PE32+)."""
        return self.optional_header is not None and self.optional_header.Magic == c_pe.IMAGE_NT_OPTIONAL_HDR64_MAGIC

    def is_reproducible(self) -> bool:
        """Return if the PE file is reproducible (i.e. has a REPRO debug entry)."""
        return self.debug is not None and any(entry.type == c_pe.IMAGE_DEBUG_TYPE.REPRO for entry in self.debug.entries)

    def pdb_path(self) -> str | None:
        """Return the PDB path, if available."""
        for entry in self.debug.entries if self.debug else []:
            if entry.type == c_pe.IMAGE_DEBUG_TYPE.CODEVIEW:
                return entry.pdb
        return None

    def _data_directory(self, index: c_pe.IMAGE_DIRECTORY_ENTRY) -> c_pe.IMAGE_DATA_DIRECTORY | None:
        """Return the data directory at the given index."""
        if not self.optional_header or not self.optional_header.DataDirectory:
            return None
        if index < 0 or index >= len(self.optional_header.DataDirectory):
            return None
        if not (entry := self.optional_header.DataDirectory[index]):
            return None
        return entry

    def data_directories(self) -> dict[c_pe.IMAGE_DIRECTORY_ENTRY, DataDirectory]:
        """Return all data directories."""
        result = {}
        for index in c_pe.IMAGE_DIRECTORY_ENTRY:
            if index == c_pe.IMAGE_DIRECTORY_ENTRY.EXPORT:
                result[index] = self.exports
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.IMPORT:
                result[index] = self.imports
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.RESOURCE:
                result[index] = self.resources
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.EXCEPTION:
                result[index] = self.exceptions
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.SECURITY and not self.virtual:
                result[index] = self.security
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.BASERELOC:
                result[index] = self.base_relocations
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.DEBUG:
                result[index] = self.debug
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.TLS:
                result[index] = self.tls
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.LOAD_CONFIG:
                result[index] = self.load_config
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.BOUND_IMPORT:
                result[index] = self.bound_import
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.IAT:
                result[index] = self.iat
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.DELAY_IMPORT:
                result[index] = self.delay_import
            elif index == c_pe.IMAGE_DIRECTORY_ENTRY.COM_DESCRIPTOR:
                result[index] = self.com_descriptor
            else:
                if entry := self._data_directory(index):
                    result[index] = DataDirectory(self, entry.VirtualAddress, entry.Size)
        return result

    @cached_property
    def exports(self) -> ExportDirectory | None:
        """Return the export directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.EXPORT)):
            return None
        return ExportDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def imports(self) -> ImportDirectory | None:
        """Return the import directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.IMPORT)):
            return None
        return ImportDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def resources(self) -> ResourceDirectory | None:
        """Return the resource directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.RESOURCE)):
            return None
        return ResourceDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def exceptions(self) -> ExceptionDirectory | None:
        """Return the exception directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.EXCEPTION)):
            return None
        return ExceptionDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def security(self) -> SecurityDirectory | None:
        """Return the security directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.SECURITY)) and not self.virtual:
            return None
        return SecurityDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def base_relocations(self) -> BaseRelocationDirectory | None:
        """Return the base relocation directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.BASERELOC)):
            return None
        return BaseRelocationDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def debug(self) -> DebugDirectory | None:
        """Return the debug directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.DEBUG)):
            return None
        return DebugDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def global_pointer(self) -> int:
        """Return the global pointer address, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.GLOBALPTR)):
            return None
        return entry.VirtualAddress

    @cached_property
    def tls(self) -> TlsDirectory | None:
        """Return the TLS (Thread Local Storage) directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.TLS)):
            return None
        return TlsDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def load_config(self) -> LoadConfigDirectory | None:
        """Return the load config directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.LOAD_CONFIG)):
            return None
        return LoadConfigDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def bound_import(self) -> BoundImportDirectory | None:
        """Return the bound import directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.BOUND_IMPORT)):
            return None
        return BoundImportDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def iat(self) -> IatDirectory | None:
        """Return the import address table (IAT) directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.IAT)):
            return None
        return IatDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def delay_import(self) -> DelayImportDirectory | None:
        """Return the delay import directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.DELAY_IMPORT)):
            return None
        return DelayImportDirectory(self, entry.VirtualAddress, entry.Size)

    @cached_property
    def com_descriptor(self) -> ComDescriptorDirectory | None:
        """Return the COM descriptor directory, if available."""
        if not (entry := self._data_directory(c_pe.IMAGE_DIRECTORY_ENTRY.COM_DESCRIPTOR)):
            return None
        return ComDescriptorDirectory(self, entry.VirtualAddress, entry.Size)

    def va_to_rva(self, va: int) -> int:
        """Return the relative virtual address (RVA) of the given virtual address (VA)."""
        return va - self.image_base

    def open(self) -> VirtualStream:
        """Return a stream of the virtual address space of the PE file."""
        return VirtualStream(self) if not self.virtual else BufferedStream(self.fh)


class Section:
    """A section in a PE file."""

    def __init__(self, pe: PE, header: c_pe.IMAGE_SECTION_HEADER):
        self.pe = pe
        self.header = header

    def __repr__(self) -> str:
        return f"<Section name={self.name!r} virtual_address={self.virtual_address:#x} virtual_size={self.virtual_size:#x} raw_size={self.raw_size:#x} pointer_to_raw_data={self.pointer_to_raw_data:#x}>"  # noqa: E501

    @classmethod
    def from_fh(cls, pe: PE, fh: BinaryIO) -> None:
        """Read a section header from the file-like object.

        Args:
            pe: The PE object to which this section belongs.
            fh: The file-like object from which to read the section header.
        """
        header = c_pe.IMAGE_SECTION_HEADER(fh)
        return cls(pe, header)

    def open(self) -> RangeStream:
        """Return a stream for the section data."""
        return SectionStream(self)

    @property
    def name(self) -> str:
        """Return the name of the section."""
        return self.header.Name.decode().strip("\x00")

    @property
    def virtual_size(self) -> int:
        """Return the virtual size of the section.

        Returns:
            The virtual size of the section as an `int`.
        """
        return self.header.Misc.VirtualSize

    @property
    def virtual_address(self) -> int:
        """Return the virtual address of the section.

        Returns:
            The virtual address of the section as an `int`.
        """
        return self.header.VirtualAddress

    @property
    def raw_size(self) -> int:
        """Return the raw size of the section.

        Returns:
            The raw size of the section as an `int`.
        """
        return self.header.SizeOfRawData

    @property
    def pointer_to_raw_data(self) -> int:
        """Return the pointer to raw data of the section.

        Returns:
            The pointer to raw data of the section as an `int`.
        """
        return self.header.PointerToRawData


class VirtualStream(AlignedStream):
    """Read from a PE file as if it's been mapped into the virtual address space."""

    def __init__(self, pe: PE):
        self.pe = pe
        self._sections = sorted(pe.sections, key=lambda s: s.virtual_address)
        self._lookup = [s.virtual_address for s in self._sections]
        super().__init__(pe.optional_header.SizeOfImage, pe.optional_header.SectionAlignment)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        # Read from the file header
        if offset < self.pe.optional_header.SizeOfHeaders:
            self.pe.fh.seek(offset)
            read_length = min(length, self.pe.optional_header.SizeOfHeaders - offset)
            result.append(self.pe.fh.read(read_length))

            length -= read_length
            offset += read_length

        section_idx = bisect_right(self._lookup, offset)

        while length > 0:
            # Read from the sections or fill in gaps
            current_section = self._sections[section_idx - 1] if section_idx > 0 else None
            next_section = self._sections[section_idx] if section_idx < len(self._sections) else None

            if not current_section and not next_section:
                # What
                result.append(b"\x00" * length)
                break

            if not current_section or offset >= current_section.virtual_address + current_section.virtual_size:
                # In between sections or after the last section
                read_length = min(length, (next_section.virtual_address if next_section else self.size) - offset)
                result.append(b"\x00" * read_length)

                length -= read_length
                offset += read_length
                section_idx += 1
                continue

            if (
                current_section.virtual_address
                <= offset
                < current_section.virtual_address + current_section.virtual_size
            ):
                # Within the current section
                offset_in_section = offset - current_section.virtual_address
                if offset_in_section < current_section.raw_size:
                    read_length = min(length, current_section.raw_size - offset_in_section)

                    self.pe.fh.seek(current_section.pointer_to_raw_data + offset_in_section)
                    result.append(self.pe.fh.read(read_length))

                    length -= read_length
                    offset += read_length
                    # Stay in the same section
                    continue

        return b"".join(result)


class SectionStream(AlignedStream):
    """A stream that reads the section data from a PE file."""

    def __init__(self, section: Section):
        self.section = section
        super().__init__(section.virtual_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        if raw_remaining := min(length, max(0, self.section.raw_size - offset)):
            self.section.pe.fh.seek(self.section.pointer_to_raw_data + offset)
            result.append(self.section.pe.fh.read(raw_remaining))
            length -= raw_remaining

        if length:
            result.append(b"\x00" * length)

        return b"".join(result)
