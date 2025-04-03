from __future__ import annotations

from collections import OrderedDict
from copy import copy
from typing import TYPE_CHECKING

from dissect.executable.exception import BuildSectionException
from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.helpers import utils

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.executable.pe.pe import PE


class PESectionManager:
    def __init__(self) -> None:
        self._sections: OrderedDict[str, PESection] = OrderedDict()
        self._patched_sections: OrderedDict[str, PESection] = OrderedDict()

    def add(self, name: str, section: PESection) -> None:
        self._sections[name] = section
        self._patched_sections[name] = PESection(section.pe, section.section, section.offset, copy(section.data))

    def last_section(self, *, patch: bool = False) -> PESection:
        sections = self.sections(patch=patch)
        return sections[next(reversed(sections))]

    def get(self, va: int = 0, name: str = "", *, patch: bool = False) -> PESection | None:
        sections = self.sections(patch=patch)

        if name:
            return sections.get(name)

        return self._in_virtual_range(va, sections.values())

    def sections(self, *, patch: bool = False) -> OrderedDict[str, PESection]:
        return self._patched_sections if patch else self._sections

    def in_range(self, va: int, *, patch: bool = False) -> PESection | None:
        """Retrieve a section pof the PE file by virtual address.

        Args:
            va: The virtual address to look for
            patch: Whether it should look through the patched sections.

        Returns:
            a `.PESection` corresponding to the virtual address

        """
        return self.get(va=va, patch=patch)

    def in_raw_range(self, offset: int, *, patch: bool = False) -> PESection | None:
        sections = self.sections(patch=patch)

        for section in sections.values():
            if section.pointer_to_raw_data <= offset < section.pointer_to_raw_data + section.size_of_raw_data:
                return section

        return None

    def from_index(self, segment_index: int, *, patch: bool = False) -> PESection:
        """Retrieve the section of the PE by index.

        Args:
            segment_index: The segment to retrieve based on the order within the PE.

        TODO: Need to check whether this works for pdb stuff

        Returns:
            A `PESection` corresponding to the segment_index.
        """
        sections = self.sections(patch=patch)

        sections_items = list(sections.items())

        idx = 0 if segment_index - 1 == -1 else segment_index
        section_name = sections_items[idx - 1][0]

        return sections[section_name]

    def _in_virtual_range(self, va: int, sections: Iterable[PESection]) -> PESection | None:
        for section in sections:
            if section.virtual_address <= va < section.virtual_address + section.virtual_size:
                return section

        return None


class PESection:
    """Base class for the PE sections that are present.

    Args:
        pe: A `PE` object.
        section: A `cstruct` definition holding the information about the section.
        offset: The offset of the section within the PE file.
        data: The data that should be part of the section, this can be used to add new sections.
    """

    def __init__(self, pe: PE, section: c_pe.IMAGE_SECTION_HEADER, offset: int, data: bytes = b""):
        self.pe = pe
        self.section = section
        self.offset = offset
        self.name = section.Name.decode().rstrip("\x00")
        self._virtual_address = section.VirtualAddress
        self._virtual_size = section.VirtualSize
        self._pointer_to_raw_data = section.PointerToRawData
        self._size_of_raw_data = section.SizeOfRawData

        # Keep track of the directories that are within this section
        self.directories: OrderedDict[int, tuple[int, int]] = OrderedDict()

        self._data = data or self.read_data()

    def directory_data(self, index: int) -> bytes:
        if (dir_information := self.directories.get(index)) is None:
            raise ValueError("Directory not found in PE Section")

        offset, size = dir_information
        return self.data[offset : offset + size]

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
    def size(self, value: int) -> None:
        """Setter to set the size of the data to the specified value.

        This function can be used to update the size of the data, but also dynamically update the offset of the data
        within the same directory.

        Args:
            value: The size of the data.
        """

        self.virtual_size = value
        self.size_of_raw_data = utils.align_int(integer=value, blocksize=self.pe.file_alignment)

    @property
    def virtual_address(self) -> int:
        """Return the virtual address of the section."""
        return self._virtual_address

    @virtual_address.setter
    def virtual_address(self, value: int) -> None:
        """Setter to set the virtual address of the section to the specified value.

        This function also updates any of the virtual addresses of the directories that are residing within the section
        itself.

        Args:
            value: The virtual address of the section.
        """

        self._virtual_address = value
        self.section.VirtualAddress = value

        # Update the VA of the directory residing within this section
        for idx, (offset, _) in self.directories.items():
            self.pe.optional_header.DataDirectory[idx].VirtualAddress = value + offset

    @property
    def virtual_size(self) -> int:
        """Return the virtual size of the section."""
        return self._virtual_size

    @virtual_size.setter
    def virtual_size(self, value: int) -> None:
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
    def pointer_to_raw_data(self, value: int) -> None:
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
    def size_of_raw_data(self, value: int) -> None:
        """Setter to set the size of the raw data to the specified value.

        The SizeOfRawData field uses the section alignment to make sure the data within this section is aligned to the
        section alignment.

        Args:
            value: The size of the data.
        """

        self._size_of_raw_data = utils.align_int(integer=value, blocksize=self.pe.file_alignment)
        self.section.SizeOfRawData = utils.align_int(integer=value, blocksize=self.pe.file_alignment)

    @property
    def data(self) -> bytes:
        """Return the data within the section."""
        return self._data[: self.virtual_size]

    @data.setter
    def data(self, value: bytes) -> None:
        """Setter to set the new data of the resource, but also dynamically update the offset of the resources within
        the same directory.

        This function currently also updates the section sizes and alignment. Ideally this would be moved to a more
        abstract function that can handle tasks like these in a more transparant manner.

        Args:
            value: The new data of the resource.
        """

        # Keep track of the section changes using the patched_sections dictionary
        section_manager = self.pe.section_manager
        patched_section: PESection = section_manager.get(name=self.name, patch=True)
        patched_section._data = value
        patched_section.size = len(value)

        # Set the new data and size
        self._data = value
        self.size = len(value)

        # Pad the remainder of the section if the SizeOfRawData is smaller than the VirtualSize
        if self.size_of_raw_data < self.virtual_size:
            self._data += utils.pad(size=self.virtual_size - self.size_of_raw_data)

        # Take note of the first section as our starting point
        first_section = next(iter(section_manager.sections(patch=True).values()))

        prev_ptr = first_section.pointer_to_raw_data
        prev_size = first_section.size_of_raw_data
        prev_va = first_section.virtual_address
        prev_vsize = first_section.virtual_size

        for section in section_manager.sections(patch=True).values():
            if section.virtual_address == prev_va:
                continue

            pointer_to_raw_data = utils.align_int(integer=prev_ptr + prev_size, blocksize=self.pe.file_alignment)
            virtual_address = utils.align_int(integer=prev_va + prev_vsize, blocksize=self.pe.section_alignment)

            if section.virtual_address < virtual_address:
                """Set the virtual address and raw pointer of the section to the new values, but only do so if the
                section virtual address is lower than the previous section. We want to prevent messing up RVA's as
                much as possible, this could lead to binaries that are a bit larger than they need to be but that
                doesn't really matter."""
                section.virtual_address = virtual_address
                section.pointer_to_raw_data = pointer_to_raw_data

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
) -> c_pe.IMAGE_SECTION_HEADER:
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
    section_header.Characteristics = c_pe.SectionFlags(characteristics)

    return section_header
