from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from dissect.executable.exception import BuildSectionException
from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.helpers import utils

if TYPE_CHECKING:
    from dissect.cstruct.cstruct import cstruct

    from dissect.executable.pe.pe import PE


class PESection:
    """Base class for the PE sections that are present.

    Args:
        pe: A `PE` object.
        section: A `cstruct` definition holding the information about the section.
        offset: The offset of the section within the PE file.
        data: The data that should be part of the section, this can be used to add new sections.
    """

    def __init__(self, pe: PE, section: cstruct, offset: int, data: bytes = b""):
        self.pe = pe
        self.section = section
        self.offset = offset
        self.name = section.Name.decode().rstrip("\x00")
        self._virtual_address = section.VirtualAddress
        self._virtual_size = section.VirtualSize
        self._pointer_to_raw_data = section.PointerToRawData
        self._size_of_raw_data = section.SizeOfRawData

        # Keep track of the directories that are within this section
        self.directories = OrderedDict()

        self._data = self.read_data() if not data else data

    def read_data(self) -> bytes:
        """Return the data within the section.

        Returns:
            The `bytes` contained within the section.
        """

        if self.pe.virtual:
            return self.pe.virtual_read(self.virtual_address, self.virtual_size)

        return self.pe.raw_read(self.pointer_to_raw_data, self.size_of_raw_data)

    @property
    def size(self) -> int:
        """Return the size of the data within the section."""
        return self.virtual_size

    @size.setter
    def size(self, value: int):
        """Setter to set the size of the data to the specified value.

        This function can be used to update the size of the data, but also dynamically update the offset of the data
        within the same directory.

        Args:
            value: The size of the data.
        """

        self.virtual_size = value
        self.size_of_raw_data = utils.align_int(
            integer=value, blocksize=self.pe.file_alignment
        )

    @property
    def virtual_address(self) -> int:
        """Return the virtual address of the section."""
        return self._virtual_address

    @virtual_address.setter
    def virtual_address(self, value: int):
        """Setter to set the virtual address of the section to the specified value.

        This function also updates any of the virtual addresses of the directories that are residing within the section
        itself.

        Args:
            value: The virtual address of the section.
        """

        self._virtual_address = value
        self.section.VirtualAddress = value

        # Update the VA of the directory residing within this section
        for idx, offset in self.directories.items():
            directory_va = value + offset
            self.pe.optional_header.DataDirectory[idx].VirtualAddress = directory_va

    @property
    def virtual_size(self) -> int:
        """Return the virtual size of the section."""
        return self._virtual_size

    @virtual_size.setter
    def virtual_size(self, value: int):
        """Setter to set the virtual size of the section to the specified value.

        Args:
            value: The virtual size of the section.
        """

        self._virtual_size = value
        self.section.VirtualSize = value

    @property
    def pointer_to_raw_data(self) -> int:
        """Return the pointer to the raw data within the section."""
        return self._pointer_to_raw_data

    @pointer_to_raw_data.setter
    def pointer_to_raw_data(self, value: int):
        """Setter to set the pointer to the raw data of the section to the specified value.

        Args:
            value: The pointer to the raw data of the section.
        """

        self._pointer_to_raw_data = value
        self.section.PointerToRawData = value

    @property
    def size_of_raw_data(self) -> int:
        """Return the size of the raw data within the section. This acounts for section alignment within the PE."""
        return self._size_of_raw_data

    @size_of_raw_data.setter
    def size_of_raw_data(self, value: int):
        """Setter to set the size of the raw data to the specified value.

        The SizeOfRawData field uses the section alignment to make sure the data within this section is aligned to the
        section alignment.

        Args:
            value: The size of the data.
        """

        self._size_of_raw_data = utils.align_int(
            integer=value, blocksize=self.pe.file_alignment
        )
        self.section.SizeOfRawData = utils.align_int(
            integer=value, blocksize=self.pe.file_alignment
        )

    @property
    def data(self) -> bytes:
        """Return the data within the section."""
        return self._data[: self.virtual_size]

    @data.setter
    def data(self, value: bytes):
        """Setter to set the new data of the resource, but also dynamically update the offset of the resources within
        the same directory.

        This function currently also updates the section sizes and alignment. Ideally this would be moved to a more
        abstract function that can handle tasks like these in a more transparant manner.

        Args:
            value: The new data of the resource.
        """

        # Keep track of the section changes using the patched_sections dictionary
        self.pe.patched_sections[self.name]._data = value
        self.pe.patched_sections[self.name].size = len(value)

        # Set the new data and size
        self._data = value
        self.size = len(value)

        # Pad the remainder of the section if the SizeOfRawData is smaller than the VirtualSize
        if self.size_of_raw_data < self.virtual_size:
            self._data += utils.pad(size=self.virtual_size - self.size_of_raw_data)

        # Take note of the first section as our starting point
        first_section = next(iter(self.pe.patched_sections.values()))

        prev_ptr = first_section.pointer_to_raw_data
        prev_size = first_section.size_of_raw_data
        prev_va = first_section.virtual_address
        prev_vsize = first_section.virtual_size

        for name, section in self.pe.patched_sections.items():
            if section.virtual_address == prev_va:
                continue

            pointer_to_raw_data = utils.align_int(
                integer=prev_ptr + prev_size, blocksize=self.pe.file_alignment
            )
            virtual_address = utils.align_int(
                integer=prev_va + prev_vsize, blocksize=self.pe.section_alignment
            )

            if section.virtual_address < virtual_address:
                """Set the virtual address and raw pointer of the section to the new values, but only do so if the
                section virtual address is lower than the previous section. We want to prevent messing up RVA's as
                much as possible, this could lead to binaries that are a bit larger than they need to be but that
                doesn't really matter."""
                self.pe.patched_sections[name].virtual_address = virtual_address
                self.pe.patched_sections[name].pointer_to_raw_data = pointer_to_raw_data

            prev_ptr = pointer_to_raw_data
            prev_size = section.size_of_raw_data
            prev_va = virtual_address
            prev_vsize = section.virtual_size

    def dump(self) -> bytes:
        """Return the section header as a `bytes` object."""
        return self.section.dumps()

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"<PESection {self.name} offset=0x{self.offset:02x} va=0x{self.virtual_address:02x} size=0x{self.virtual_size:02x}>"  # noqa: E501


def build_section(
    virtual_size: int,
    virtual_address: int,
    raw_size: int,
    pointer_to_raw_data: int,
    name: str | bytes = b".dissect",
    characteristics: int = 0xC0000040,
) -> cstruct:
    """Build a new section for the PE.

    Args:
        virtual_size: The virtual size of the new section data.
        virtual_address: The virtual address where the new section is located.
        raw_size: The size of the section data.
        pointer_to_raw_data: The pointer to the raw data of the new section.
        characteristics: The characteristics of the new section, default: 0xC0000040
        name: The new section name, default: .dissect

    Returns:
        The new section header as a `cstruct` object.
    """

    if len(name) > 8:
        raise BuildSectionException("section names can't be longer than 8 characters")

    if isinstance(name, str):
        name = name.encode()

    section_header = c_pe.IMAGE_SECTION_HEADER()

    section_header.Name = name + utils.pad(size=8 - len(name))
    section_header.VirtualSize = virtual_size
    section_header.VirtualAddress = virtual_address
    section_header.SizeOfRawData = raw_size
    section_header.PointerToRawData = pointer_to_raw_data
    section_header.PointerToRelocations = 0
    section_header.PointerToLinenumbers = 0
    section_header.NumberOfRelocations = 0
    section_header.NumberOfLinenumbers = 0
    section_header.Characteristics = characteristics

    return section_header
