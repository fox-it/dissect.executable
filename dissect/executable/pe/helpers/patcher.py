from __future__ import annotations

import copy
import struct
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.helpers import utils

if TYPE_CHECKING:
    from dissect.executable import PE
    from dissect.executable.pe.helpers.sections import PESection


class Patcher:
    """Class that is used to patch existing PE files with the changes made by the user.

    Args:
        pe: A `PE` object that contains the original PE file.
    """

    def __init__(self, pe: PE):
        self.pe = pe
        self.patched_pe = BytesIO()
        self.functions = []

    @property
    def build(self) -> BytesIO:
        """Build the patched PE file.

        This function will return a new PE file as a `BytesIO` object that contains the new PE file.

        Returns:
            The patched PE file as a `BytesIO` object.
        """

        # Update the SizeOfImage
        self.pe.optional_header.SizeOfImage = self.pe_size

        self.patched_pe.seek(0)

        # Build the section table and add the sections
        self._build_section_table()

        # Apply the patches
        self._patch_rvas()

        # Add the MZ, File and NT headers
        self.patched_pe.seek(0)
        self._build_dos_header()

        # Reset the file pointer
        self.patched_pe.seek(0)
        return self.patched_pe

    @property
    def pe_size(self) -> int:
        """Calculate the new PE size.

        We can calculate the new size of the PE by looking at the ending of the last section.

        Returns:
            The new size of the PE as an `int`.
        """

        last_section = self.pe.patched_sections[next(reversed(self.pe.patched_sections))]
        va = last_section.virtual_address
        size = last_section.virtual_size

        return utils.align_int(integer=va + size, blocksize=self.pe.optional_header.SectionAlignment)

    def seek(self, address: int) -> None:
        """Seek that is used to seek to a virtual address in the patched PE file.

        Args:
            address: The virtual address to seek to.
        """

        raw_address = self.pe.virtual_address(address=address)
        self.patched_pe.seek(raw_address)

    def _build_section_table(self) -> None:
        """Function to build the section table and add the sections with their data."""

        if self.patched_pe.tell() < self.pe.section_header_offset:
            # Pad the patched file with null bytes until we reach the section header offset
            self.patched_pe.write(utils.pad(size=self.pe.section_header_offset - self.patched_pe.tell()))

        # Write the section headers
        for section in self.pe.patched_sections.values():
            self.patched_pe.write(section.dump())

        # Add the data for each section
        for section in self.pe.patched_sections.values():
            self.patched_pe.seek(section.pointer_to_raw_data)
            self.patched_pe.write(section.data)

    def _build_dos_header(self) -> None:
        """Function to build the DOS header, NT headers and the DOS stub."""

        # Add the MZ
        self.patched_pe.write(self.pe.mz_header.dumps())

        # Add the DOS stub
        stub_size = self.pe.mz_header.e_lfanew - self.patched_pe.tell()
        dos_stub = self.pe.raw_read(offset=self.patched_pe.tell(), size=stub_size)
        self.patched_pe.write(dos_stub)

        # Add the NT headers
        self.patched_pe.seek(self.pe.mz_header.e_lfanew)
        self.patched_pe.write(b"PE\x00\x00")
        self.patched_pe.write(self.pe.file_header.dumps())
        self.patched_pe.write(self.pe.optional_header.dumps())

    def _patch_rvas(self) -> None:
        """Function to call the different patch functions responsible for patching any kind of relative addressing."""

        self._patch_import_rvas()
        self._patch_export_rvas()
        self._patch_rsrc_rvas()
        self._patch_tls_rvas()

    def _patch_import_rvas(self) -> None:
        """Function to patch the RVAs of the import directory and the thunkdata entries."""

        patched_import_data = bytearray()

        # Get the directory entry virtual adddress, this is the updated address if it has been patched.
        directory_va = self.pe.directory_va(c_pe.IMAGE_DIRECTORY_ENTRY_IMPORT)
        if not directory_va:
            return

        # Get the original VA of the section the import directory is residing in, this value is used to calculate the
        # new RVA's
        section = self.pe.patched_section(va=directory_va)
        directory_offset = directory_va - section.virtual_address
        original_directory_va = self.pe.sections[section.name].virtual_address + directory_offset

        # Loop over the imports of the PE to patch the RVA's of the import descriptors and the associated thunkdata
        # entries
        for name, module in self.pe.imports.items():
            import_descriptor = module.import_descriptor
            patched_thunkdata = bytearray()

            if import_descriptor.Name != 0xFFFFF800 and import_descriptor.Name != 0x0:
                old_first_thunk = import_descriptor.FirstThunk

                first_thunk_offset = old_first_thunk - original_directory_va
                import_descriptor.FirstThunk = abs(directory_va + first_thunk_offset)

                import_descriptor.OriginalFirstThunk = import_descriptor.FirstThunk

                name_offset = import_descriptor.Name - original_directory_va
                import_descriptor.Name = abs(directory_va + name_offset)

                for function in module.functions:
                    thunkdata = function.thunkdata
                    # Check if we're dealing with an ordinal entry, if it's an ordinal entry we don't need
                    # to patch since it's not an RVA
                    if function.ordinal:
                        patched_thunkdata += thunkdata.dumps()
                        continue

                    # Check the original RVA associated with the AddressOfData field in the thunkdata, retrieve the
                    # original VA
                    # and use it to also select the patched virtual address of this section that the RVA is located in
                    for name, section in self.pe.sections.items():
                        if thunkdata.u1.AddressOfData in range(
                            section.virtual_address,
                            section.virtual_address + section.virtual_size,
                        ):
                            virtual_address = section.virtual_address
                            new_virtual_address = self.pe.patched_sections[name].virtual_address
                            break

                    # Calculate the offset using the VA of the section and update the thunkdata
                    va_offset = thunkdata.u1.AddressOfData - virtual_address
                    new_thunkdata = new_virtual_address + va_offset
                    thunkdata.u1.AddressOfData = new_thunkdata
                    thunkdata.u1.ForwarderString = new_thunkdata
                    thunkdata.u1.Function = new_thunkdata
                    thunkdata.u1.Ordinal = new_thunkdata

                    patched_thunkdata += thunkdata.dumps()

                # Write the thunk data into the patched PE
                self.seek(import_descriptor.FirstThunk)
                self.patched_pe.write(patched_thunkdata)

                patched_import_data += import_descriptor.dumps()

        self.seek(directory_va)
        self.patched_pe.write(patched_import_data)

    def _patch_export_rvas(self) -> None:
        """Function to patch the RVAs of the export directory and the associated function and name RVA's."""

        directory_va = self.pe.directory_va(c_pe.IMAGE_DIRECTORY_ENTRY_EXPORT)
        if not directory_va:
            return

        self.seek(directory_va)
        export_directory = c_pe.IMAGE_EXPORT_DIRECTORY(self.patched_pe)

        # Get the original VA of the section the import directory is residing in, this value is used to calculate the
        # new RVA's
        section = self.pe.patched_section(va=directory_va)
        directory_offset = directory_va - section.virtual_address
        original_directory_va = self.pe.sections[section.name].virtual_address + directory_offset

        name_offset = export_directory.Name - original_directory_va
        address_of_functions_offset = export_directory.AddressOfFunctions - original_directory_va
        address_of_names_offset = export_directory.AddressOfNames - original_directory_va
        address_of_name_ordinals = export_directory.AddressOfNameOrdinals - original_directory_va

        export_directory.Name = directory_va + name_offset
        export_directory.AddressOfFunctions = directory_va + address_of_functions_offset
        export_directory.AddressOfNames = directory_va + address_of_names_offset
        export_directory.AddressOfNameOrdinals = directory_va + address_of_name_ordinals

        # Write the new export directory
        self.seek(directory_va)
        self.patched_pe.write(export_directory.dumps())

        # Patch the addresses of the functions
        new_function_rvas = []
        function_rvas = bytearray()
        self.seek(export_directory.AddressOfFunctions)
        export_addresses = c_pe.uint32[export_directory.NumberOfFunctions].read(self.patched_pe)
        for address in export_addresses:
            section = self.pe.section(va=address)
            if not section:
                continue
            address_offset = address - section.virtual_address
            new_address = self.pe.patched_sections[section.name].virtual_address + address_offset
            new_function_rvas.append(new_address)

        for rva in new_function_rvas:
            function_rvas += struct.pack("<I", rva)

        self.seek(export_directory.AddressOfFunctions)
        self.patched_pe.write(function_rvas)

        # Patch the addresses of the names
        new_name_rvas = []
        name_rvas = bytearray()
        self.seek(export_directory.AddressOfNames)
        export_names = c_pe.uint32[export_directory.NumberOfNames].read(self.patched_pe)
        for name_address in export_names:
            section = self.pe.section(va=name_address)
            address_offset = name_address - section.virtual_address
            new_address = self.pe.patched_sections[section.name].virtual_address + address_offset
            new_name_rvas.append(new_address)

        for name_rva in new_name_rvas:
            name_rvas += struct.pack("<I", name_rva)

        self.seek(export_directory.AddressOfNames)
        self.patched_pe.write(name_rvas)
        # self.pe.optional_header.DataDirectory[c_pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size = len(name_rvas)

    def _patch_rsrc_rvas(self) -> None:
        """Function to patch the RVAs of the resource directory and the associated resource data RVA's."""

        directory_va = self.pe.directory_va(c_pe.IMAGE_DIRECTORY_ENTRY_RESOURCE)
        if not directory_va:
            return

        section_data = BytesIO()
        self.seek(directory_va)

        for rsrc_entry in sorted(self.pe.raw_resources, key=lambda rsrc: rsrc["data_offset"]):
            entry_offset = rsrc_entry["offset"]
            entry = rsrc_entry["entry"]

            if isinstance(entry, c_pe.IMAGE_RESOURCE_DATA_ENTRY):
                rsrc_obj = rsrc_entry["resource"]
                data_offset = rsrc_entry["data_offset"]

                # Update the offset of the entry to match with the new directory VA
                rsrc_obj.offset = directory_va + data_offset

                # Write the resource entry data into the section
                section_data.seek(data_offset)
                section_data.write(rsrc_obj.data)

            # Write the resource entry into the section
            section_data.seek(entry_offset)
            section_data.write(entry.dumps())

        section_data.seek(0)
        self.seek(directory_va)
        self.patched_pe.write(section_data.read())

    def _patch_tls_rvas(self) -> None:
        """Function to patch the RVAs of the TLS directory and the associated TLS callbacks."""

        directory_va = self.pe.directory_va(c_pe.IMAGE_DIRECTORY_ENTRY_TLS)
        if not directory_va:
            return

        self.seek(directory_va)
        tls_directory = self.pe.tls_mgr._tls_directory(self.patched_pe)

        image_base = self.pe.optional_header.ImageBase

        # Patch the TLS StartAddressOfRawData and EndAddressOfRawData
        section = self.pe.section(va=tls_directory.StartAddressOfRawData - image_base)
        start_address_offset = tls_directory.StartAddressOfRawData - section.virtual_address
        tls_directory.StartAddressOfRawData = (
            self.pe.patched_sections[section.name].virtual_address + start_address_offset
        )
        end_address_offset = tls_directory.EndAddressOfRawData - tls_directory.StartAddressOfRawData
        tls_directory.EndAddressOfRawData = tls_directory.StartAddressOfRawData + end_address_offset

        # Patch the TLS callbacks address
        section = self.pe.section(va=tls_directory.AddressOfCallBacks - image_base)
        address_of_callbacks_offset = tls_directory.AddressOfCallBacks - section.virtual_address
        tls_directory.AddressOfCallBacks = (
            self.pe.patched_sections[section.name].virtual_address + address_of_callbacks_offset
        )

        # Patch the TLS AddressOfIndex
        section = self.pe.section(va=tls_directory.AddressOfIndex - image_base)
        address_of_index_offset = tls_directory.AddressOfIndex - self.pe.sections[section.name].virtual_address
        tls_directory.AddressOfIndex = self.pe.sections[section.name].virtual_address + address_of_index_offset

        # Write the patched TLS directory to the new PE
        self.seek(directory_va)
        self.patched_pe.write(tls_directory.dumps())

    def _get_tls_attribute_section(self, va: int) -> PESection | None:
        """Function to get the section that contains the TLS attribute.

        Args:
            va: The virtual address of the TLS attribute.

        Returns:
            The section that contains the TLS attribute as a `PESection` object.
        """

        for section in self.pe.sections.values():
            if va in range(section.virtual_address, section.virtual_address + section.virtual_size):
                return section
        return None
