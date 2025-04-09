from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.helpers.utils import DictManager

if TYPE_CHECKING:
    from dissect.executable.pe.helpers.sections import PESection
    from dissect.executable.pe.pe import PE


@dataclass
class ExportFunction:
    """Object to store the information belonging to export functions.

    Args:
        ordinal: The ordinal of the export function.
        address: The export function address.
        name: The name of the function, if available.
    """

    ordinal: int
    address: int
    name: bytes | None = b""

    def __str__(self) -> str:
        return self.name.decode() if self.name else f"#{self.ordinal}"

    def __repr__(self) -> str:
        return f"<Export {self}>"


class ExportManager(DictManager[ExportFunction]):
    def __init__(self, pe: PE, section: PESection):
        super().__init__(pe, section)

        self.parse()

    def parse(self) -> None:
        """Parse the export directory of the PE file.

        This function will store every export function within the PE file as an `ExportFunction` object containing the
        name (if available), the call ordinal, and the function address.
        """

        export_entry_va = self.pe.directory_entry_rva(c_pe.IMAGE_DIRECTORY_ENTRY_EXPORT)
        export_entry = BytesIO(self.section.directory_data(index=c_pe.IMAGE_DIRECTORY_ENTRY_EXPORT))
        export_directory = c_pe.IMAGE_EXPORT_DIRECTORY(export_entry)

        # Seek to the offset of the export name
        export_entry.seek(export_directory.Name - export_entry_va)
        self.export_name = c_pe.char[None](export_entry)

        # Create a list of adresses for the exported functions
        export_entry.seek(export_directory.AddressOfFunctions - export_entry_va)
        export_addresses: list[int] = c_pe.uint32[export_directory.NumberOfFunctions].read(export_entry)
        # Create a list of addresses for the exported functions that have associated names
        export_entry.seek(export_directory.AddressOfNames - export_entry_va)
        export_names: list[int] = c_pe.uint32[export_directory.NumberOfNames].read(export_entry)
        # Create a list of addresses for the ordinals associated with the functions
        export_entry.seek(export_directory.AddressOfNameOrdinals - export_entry_va)
        export_ordinals: list[int] = c_pe.uint16[export_directory.NumberOfNames].read(export_entry)

        # Iterate over the export functions and store the information
        export_entry.seek(export_directory.AddressOfFunctions - export_entry_va)
        for idx, address in enumerate(export_addresses):
            _idx = idx + 1
            key = str(_idx)
            export_name: bytes | None = None

            if idx in export_ordinals:
                entry_offset = export_names[export_ordinals.index(idx)] - export_entry_va
                export_entry.seek(entry_offset)
                export_name = c_pe.char[None](export_entry)
                key = export_name.decode()

            self.elements[key] = ExportFunction(ordinal=export_directory.Base + _idx, address=address, name=export_name)
