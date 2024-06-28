from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

# Local imports
from dissect.executable.pe.helpers.c_pe import pestruct

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
        self.relocations = []

        self.parse_relocations()

    def parse_relocations(self):
        """Parse the relocation table of the PE file."""

        reloc_data = BytesIO(self.pe.read_image_directory(index=pestruct.IMAGE_DIRECTORY_ENTRY_BASERELOC))
        reloc_data_size = reloc_data.getbuffer().nbytes
        while reloc_data.tell() < reloc_data_size:
            reloc_directory = pestruct.IMAGE_BASE_RELOCATION(reloc_data)
            if not reloc_directory.VirtualAddress:
                # End of relocation entries
                break

            # Each entry consists of 2 bytes
            number_of_entries = (reloc_directory.SizeOfBlock - len(reloc_directory.dumps())) // 2
            entries = []
            for _ in range(0, number_of_entries):
                entry = pestruct.uint16(reloc_data)
                if entry:
                    entries.append(entry)

            self.relocations.append(
                {"rva:": reloc_directory.VirtualAddress, "number_of_entries": number_of_entries, "entries": entries}
            )

    def add(self):
        raise NotImplementedError
