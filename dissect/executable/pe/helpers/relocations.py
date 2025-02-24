from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe

if TYPE_CHECKING:
    from dissect.executable.pe.helpers.sections import PESection
    from dissect.executable.pe.pe import PE


class RelocationManager:
    """Base class for dealing with the relocations within the PE file.

    Args:
        pe: The PE file object.
        section: The section object that contains the relocation table.
    """

    def __init__(self, pe: PE, section: PESection):
        self.pe = pe
        self.section = section
        self.relocations: list[dict] = []

        self.parse_relocations()

    def parse_relocations(self) -> None:
        """Parse the relocation table of the PE file."""

        reloc_data = BytesIO(self.pe.read_image_directory(index=c_pe.IMAGE_DIRECTORY_ENTRY_BASERELOC))
        reloc_data_size = reloc_data.getbuffer().nbytes
        while reloc_data.tell() < reloc_data_size:
            reloc_directory = c_pe.IMAGE_BASE_RELOCATION(reloc_data)
            if not reloc_directory.VirtualAddress:
                # End of relocation entries
                break

            # Each entry consists of 2 bytes
            number_of_entries = (reloc_directory.SizeOfBlock - len(reloc_directory.dumps())) // 2
            entries = [entry for _ in range(number_of_entries) if (entry := c_pe.uint16(reloc_data))]

            self.relocations.append(
                {
                    "rva:": reloc_directory.VirtualAddress,
                    "number_of_entries": number_of_entries,
                    "entries": entries,
                }
            )

    def add(self) -> None:
        raise NotImplementedError
