from __future__ import annotations

import struct
from collections import OrderedDict
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO, Generator

from dissect.executable.pe.helpers import utils

# Local imports
from dissect.executable.pe.helpers.c_pe import pestruct

if TYPE_CHECKING:
    from dissect.cstruct.cstruct import cstruct

    from dissect.executable.pe.helpers.sections import PESection
    from dissect.executable.pe.pe import PE


class ImportModule:
    """Base class for the import modules, these hold their respective functions.

    Args:
        name: The name of the module.
        import_descriptor: The import descriptor of the module as a cstruct object.
        module_va: The virtual address of the module.
        name_va: The virtual address of the name of the module.
        first_thunk: The virtual address of the first thunk.
    """

    def __init__(self, name: bytes, import_descriptor: cstruct, module_va: int, name_va: int, first_thunk: int):
        self.name = name
        self.import_descriptor = import_descriptor
        self.module_va = module_va
        self.name_va = name_va
        self.first_thunk = first_thunk
        self.functions = []

    def __str__(self) -> str:
        return self.name.decode()

    def __repr__(self) -> str:
        return f"<ImportModule {self.name.decode()} va=0x{self.module_va:02x} first_thunk=0x{self.first_thunk:02x} functions={self.functions}>"  # noqa: E501


class ImportFunction:
    """Base class for the import functions.

    Args:
        pe: A `PE` object.
        thunkdata: The thunkdata of the import function as a cstruct object.
    """

    def __init__(self, pe: PE, thunkdata: cstruct, name: str = ""):
        self.pe = pe
        self.thunkdata = thunkdata
        self._name = name

    @property
    def name(self) -> str:
        """Return the name of the import function if available, otherwise return the ordinal of the function.

        Returns:
            The name or ordinal of the import function.
        """

        if self._name:
            return self._name

        ordinal = self.thunkdata.u1.AddressOfData & self.pe._high_bit

        if not ordinal:
            self.pe.seek(self.thunkdata.u1.AddressOfData + 2)
            entry = pestruct.char[None](self.pe).decode()
        else:
            entry = ordinal

        if isinstance(entry, int):
            return str(entry)

        return entry

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"<ImportFunction {self.name}>"


class ImportManager:
    """The base class for dealing with the imports that are present within the PE file.

    Args:
        pe: A `PE` object.
        section: The associated `PESection` object.
    """

    def __init__(self, pe: PE, section: PESection):
        self.pe = pe
        self.section = section
        self.import_directory_rva = 0
        self.import_data = bytearray()
        self.new_size_of_image = 0
        self.section_data = bytearray()
        self.imports = OrderedDict()
        self.thunks = []

        self.parse_imports()

    def parse_imports(self):
        """Parse the imports of the PE file.

        The imports are in turn added to the `imports` attribute so they can be accessed by the user.
        """

        import_data = BytesIO(self.pe.read_image_directory(index=pestruct.IMAGE_DIRECTORY_ENTRY_IMPORT))
        import_data.seek(0)

        # Loop over the entries
        for descriptor_va, import_descriptor in self.import_descriptors(import_data=import_data):
            if import_descriptor.Name != 0xFFFFF800 and import_descriptor.Name != 0x0:
                self.pe.seek(import_descriptor.Name)
                modulename = pestruct.char[None](self.pe)

                # Use the OriginalFirstThunk if available, FirstThunk otherwise
                first_thunk = (
                    import_descriptor.FirstThunk
                    if not import_descriptor.OriginalFirstThunk
                    else import_descriptor.OriginalFirstThunk
                )
                module = ImportModule(
                    name=modulename,
                    import_descriptor=import_descriptor,
                    module_va=descriptor_va,
                    name_va=import_descriptor.Name,
                    first_thunk=first_thunk,
                )

                for thunkdata in self.parse_thunks(offset=first_thunk):
                    module.functions.append(ImportFunction(pe=self.pe, thunkdata=thunkdata))

                self.imports[modulename.decode()] = module

    def import_descriptors(self, import_data: BinaryIO) -> Generator[tuple[int, cstruct], None, None]:
        """Parse the import descriptors of the PE file.

        Args:
            import_data: The data within the import directory.

        Yields:
            The import descriptor as a `cstruct` object.
        """

        while True:
            try:
                import_descriptor = pestruct.IMAGE_IMPORT_DESCRIPTOR(import_data)
            except EOFError:
                break

            yield import_data.tell(), import_descriptor

    def parse_thunks(self, offset: int) -> Generator[cstruct, None, None]:
        """Parse the import thunks for every module.

        Args:
            offset: The offset to the first thunk

        Yields:
            The function name or ordinal
        """

        self.pe.seek(offset)

        while True:
            thunkdata = self.pe.image_thunk_data(self.pe)
            if not thunkdata.u1.Function:
                break

            yield thunkdata

    def add(self, dllname: str, functions: list):
        """Add the given module and its functions to the PE.

        Args:
            dllname: The name of the module to add.
            functions: A `list` of function names belonging to the module.
        """

        self.last_section = self.pe.patched_sections[next(reversed(self.pe.patched_sections))]

        # Build a dummy import module
        self.imports[dllname] = ImportModule(
            name=dllname.encode(), import_descriptor=None, module_va=0, name_va=0, first_thunk=0
        )
        # Build the dummy module functions
        for function in functions:
            self.pe.imports[dllname].functions.append(ImportFunction(pe=self.pe, thunkdata=None, name=function))

        # Rebuild the import table with the new import module and functions
        self.build_import_table()

    def delete(self, dllname: str, functions: list):
        raise NotImplementedError

    def build_import_table(self):
        """Function to rebuild the import table after a change has been made to the PE imports.

        Currently we're using the .idata section to store the imports, there might be a better way to do this but for
        now this will do.
        """

        # Reset the known thunkdata
        self.thunks = []

        import_descriptors = []
        self.import_data = bytearray()

        for name, module in self.imports.items():
            # Take note of the current offset to store the modulename
            name_offset = len(self.import_data)
            self.import_data += name.encode() + b"\x00"

            # Build the module imports and get the RVA of the first thunk to generate an import descriptor
            first_thunk_rva = self._build_module_imports(functions=module.functions)
            import_descriptor = self._build_import_descriptor(
                first_thunk_rva=first_thunk_rva, name_rva=self.pe.optional_header.SizeOfImage + name_offset
            )
            import_descriptors.append(import_descriptor)

        datadirectory_size = 0
        for idx, descriptor in enumerate(import_descriptors):
            if idx == 0:
                # Take note of the RVA of the first import descriptor
                import_rva = self.pe.optional_header.SizeOfImage + len(self.import_data)
            self.import_data += descriptor.dumps()
            datadirectory_size += len(descriptor)

        # Create a new section
        section_data = utils.align_data(data=self.import_data, blocksize=self.pe.file_alignment)
        size = len(self.import_data) + pestruct.IMAGE_SECTION_HEADER.size
        self.pe.add_section(
            name=".idata",
            data=section_data,
            datadirectory=pestruct.IMAGE_DIRECTORY_ENTRY_IMPORT,
            datadirectory_rva=import_rva,
            datadirectory_size=datadirectory_size,
            size=size,
        )

    def _build_module_imports(self, functions: list[ImportFunction]) -> int:
        """Function to build the imports for a module.

        This function is responsible for building the functions by name, as well as the associated thunkdata that is
        used to parse the imports at a later stage.

        Args:
            functions: A `list` of `ImportFunction` objects.

        Returns:
            The relative virtual address of the first thunk.
        """

        function_offsets = []

        for idx, function in enumerate(functions):
            function_offsets.append(len(self.import_data))
            self.import_data += struct.pack("<H", idx)  # Hint
            self.import_data += function.name.encode() + b"\x00"  # Name

        first_thunk_rva = self.pe.optional_header.SizeOfImage + len(self.import_data)

        # Build the function thunkdata
        thunkdata = self._build_thunkdata(import_rvas=function_offsets)
        self.import_data += thunkdata

        return first_thunk_rva

    def _build_thunkdata(self, import_rvas: list[int]) -> bytes:
        """Function to build the thunkdata for the new import table.

        Args:
            import_rvas: A `list` of relative virtual addresses.

        Returns:
            The thunkdata as a `bytes` object.
        """

        thunkdata = bytearray()
        for rva in import_rvas:
            rva += self.pe.optional_header.SizeOfImage
            thunkdata += (
                struct.pack("<Q", rva)
                if self.pe.file_header.Machine == pestruct.MachineType.IMAGE_FILE_MACHINE_AMD64
                else struct.pack("<L", rva)
            )

        # Add the thunkdata delimiter
        thunkdata += (
            struct.pack("<Q", 0)
            if self.pe.file_header.Machine == pestruct.MachineType.IMAGE_FILE_MACHINE_AMD64
            else struct.pack("<L", 0)
        )

        self.thunks.append(self.pe.image_thunk_data(thunkdata))

        return thunkdata

    def _build_import_descriptor(self, first_thunk_rva: int, name_rva: int) -> cstruct:
        """Function to build the import descriptor for the new import table.

        Args:
            first_thunk_rva: The relative address of the first piece of thunkdata.

        Returns:
            The image import descriptor as a `cstruct` object.
        """

        new_import_descriptor = pestruct.IMAGE_IMPORT_DESCRIPTOR()

        new_import_descriptor.OriginalFirstThunk = first_thunk_rva
        new_import_descriptor.TimeDateStamp = 0
        new_import_descriptor.ForwarderChain = 0
        new_import_descriptor.Name = name_rva
        new_import_descriptor.FirstThunk = first_thunk_rva

        return new_import_descriptor