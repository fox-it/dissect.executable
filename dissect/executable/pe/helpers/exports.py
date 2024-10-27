from __future__ import annotations

from collections import OrderedDict
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe

if TYPE_CHECKING:
    from dissect.executable.pe.helpers.sections import PESection
    from dissect.executable.pe.pe import PE


class ExportFunction:
    """Object to store the information belonging to export functions.

    Args:
        ordinal: The ordinal of the export function.
        address: The export function address.
        name: The name of the function, if available.
    """

    def __init__(self, ordinal: int, address: int, name: bytes = b""):
        self.ordinal = ordinal
        self.address = address
        self.name = name

    def __str__(self) -> str:
        return self.name.decode() if self.name else self.ordinal

    def __repr__(self) -> str:
        return (
            f"<Export {self.name.decode()}>"
            if self.name
            else f"<Export #{self.ordinal}>"
        )


class ExportManager:
    def __init__(self, pe: PE, section: PESection):
        self.pe = pe
        self.section = section
        self.exports = OrderedDict()

        self.parse_exports()

    def parse_exports(self) -> None:
        """Parse the export directory of the PE file.

        This function will store every export function within the PE file as an `ExportFunction` object containing the
        name (if available), the call ordinal, and the function address.
        """

        export_entry_va = self.pe.directory_va(c_pe.IMAGE_DIRECTORY_ENTRY_EXPORT)
        export_entry = BytesIO(
            self.pe.read_image_directory(index=c_pe.IMAGE_DIRECTORY_ENTRY_EXPORT)
        )
        export_directory = c_pe.IMAGE_EXPORT_DIRECTORY(export_entry)

        # Seek to the offset of the export name
        export_entry.seek(export_directory.Name - export_entry_va)
        self.export_name = c_pe.char[None](export_entry)

        # Create a list of adresses for the exported functions
        export_entry.seek(export_directory.AddressOfFunctions - export_entry_va)
        export_addresses = c_pe.uint32[export_directory.NumberOfFunctions].read(
            export_entry
        )
        # Create a list of addresses for the exported functions that have associated names
        export_entry.seek(export_directory.AddressOfNames - export_entry_va)
        export_names = c_pe.uint32[export_directory.NumberOfNames].read(export_entry)
        # Create a list of addresses for the ordinals associated with the functions
        export_entry.seek(export_directory.AddressOfNameOrdinals - export_entry_va)
        export_ordinals = c_pe.uint16[export_directory.NumberOfNames].read(export_entry)

        # Iterate over the export functions and store the information
        export_entry.seek(export_directory.AddressOfFunctions - export_entry_va)
        for idx, address in enumerate(export_addresses):
            if idx in export_ordinals:
                export_entry.seek(
                    export_names[export_ordinals.index(idx)] - export_entry_va
                )
                export_name = c_pe.char[None](export_entry)
                self.exports[export_name.decode()] = ExportFunction(
                    ordinal=idx + 1, address=address, name=export_name
                )
            else:
                export_name = None
                self.exports[str(idx + 1)] = ExportFunction(
                    ordinal=idx + 1, address=address, name=export_name
                )

    def add(self):
        raise NotImplementedError

    def delete(self):
        raise NotImplementedError
