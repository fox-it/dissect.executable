from __future__ import annotations

from collections import OrderedDict
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.helpers import utils
from dissect.executable.pe.helpers.utils import create_struct

if TYPE_CHECKING:
    from collections.abc import Iterator

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

    def __init__(
        self,
        name: bytes,
        import_descriptor: c_pe.IMAGE_IMPORT_DESCRIPTOR,
        module_va: int,
        name_va: int,
        first_thunk: int,
    ):
        self.name = name
        self.import_descriptor = import_descriptor
        self.module_va = module_va
        self.name_va = name_va
        self.first_thunk = first_thunk
        self.functions: list[ImportFunction] = []

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

    def __init__(
        self,
        pe: PE,
        thunkdata: c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64,
        high_bit: int,
        name: str = "",
    ):
        self.pe = pe
        self.thunkdata = thunkdata
        self.high_bit = high_bit
        self._name = name

    @property
    def data_address(self) -> int:
        """Shows the AddressOfData of the thunk data."""
        return self.thunkdata.u1.AddressOfData

    @property
    def ordinal(self) -> int:
        return self.data_address & self.high_bit

    @property
    def name(self) -> str:
        """Return the name of the import function if available, otherwise return the ordinal of the function.

        Returns:
            The name or ordinal of the import function.
        """

        if self._name:
            return self._name

        if self.thunkdata is None:
            # For the case thunkdata is not defined, such as during the `add`
            return ""

        if not (entry := self.ordinal):
            self.pe.seek(self.data_address + 2)
            entry = c_pe.char[None](self.pe).decode()

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
        self.image_size: int = self.pe.optional_header.SizeOfImage
        self.section = section
        self.import_directory_rva = 0
        self.import_data = bytearray()
        self.new_size_of_image = 0
        self.section_data = bytearray()
        self.imports: OrderedDict[str, ImportModule] = OrderedDict()
        self.thunks: list[c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64] = []

        self._thunk_data: type[c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64] = None
        self._high_bit: int = 0

        self.set_architecture(pe)
        self.parse_imports()

    def set_architecture(self, pe: PE) -> None:
        if pe.is64bit():
            self._thunk_data = c_pe.IMAGE_THUNK_DATA64
            self._high_bit = 1 << 63
        else:
            self._thunk_data = c_pe.IMAGE_THUNK_DATA32
            self._high_bit = 1 << 31

    def parse_imports(self) -> None:
        """Parse the imports of the PE file.

        The imports are in turn added to the `imports` attribute so they can be accessed by the user.
        """
        import_data = BytesIO(self.section.directory_data(index=c_pe.IMAGE_DIRECTORY_ENTRY_IMPORT))

        # Loop over the entries
        for descriptor_va, import_descriptor in self.import_descriptors(import_data=import_data):
            if import_descriptor.Name in [0xFFFFF800, 0x0]:
                continue

            self.pe.seek(import_descriptor.Name)
            modulename: bytes = c_pe.char[None](self.pe)

            # Use the OriginalFirstThunk if available, FirstThunk otherwise
            first_thunk = import_descriptor.OriginalFirstThunk or import_descriptor.FirstThunk

            module = ImportModule(
                name=modulename,
                import_descriptor=import_descriptor,
                module_va=descriptor_va,
                name_va=import_descriptor.Name,
                first_thunk=first_thunk,
            )

            module.functions.extend(
                ImportFunction(pe=self.pe, thunkdata=thunkdata, high_bit=self._high_bit)
                for thunkdata in self.parse_thunks(offset=first_thunk)
            )
            self.imports[modulename.decode()] = module

    def import_descriptors(self, import_data: BinaryIO) -> Iterator[tuple[int, c_pe.IMAGE_IMPORT_DESCRIPTOR]]:
        """Parse the import descriptors of the PE file.

        Args:
            import_data: The data within the import directory.

        Yields:
            The import descriptor as a `cstruct` object.
        """

        while True:
            try:
                import_descriptor = c_pe.IMAGE_IMPORT_DESCRIPTOR(import_data)
            except EOFError:
                break

            yield import_data.tell(), import_descriptor

    def parse_thunks(self, offset: int) -> Iterator[c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64]:
        """Parse the import thunks for every module.

        Args:
            offset: The offset to the first thunk

        Yields:
            The function name or ordinal
        """

        self.pe.seek(offset)

        while True:
            thunkdata = self._thunk_data(self.pe)
            if not thunkdata.u1.Function:
                break

            yield thunkdata

    def add(self, dllname: str, functions: list[str]) -> None:
        """Add the given module and its functions to the PE.

        Args:
            dllname: The name of the module to add.
            functions: A `list` of function names belonging to the module.
        """

        self.last_section = self.pe.sections.last_section(patch=True)

        # Build a dummy import module
        _module = ImportModule(
            name=dllname.encode(),
            import_descriptor=None,
            module_va=0,
            name_va=0,
            first_thunk=0,
        )
        # Build the dummy module functions
        _module.functions.extend(
            ImportFunction(pe=self.pe, thunkdata=None, high_bit=self._high_bit, name=function) for function in functions
        )

        self.imports[dllname] = _module

        # Rebuild the import table with the new import module and functions
        self.build_import_table()

    def delete(self, dllname: str, functions: list) -> None:
        raise NotImplementedError

    def build_import_table(self) -> None:
        """Function to rebuild the import table after a change has been made to the PE imports.

        Currently we're using the .idata section to store the imports, there might be a better way to do this but for
        now this will do.
        """

        # Reset the known thunkdata
        self.thunks = []

        import_descriptors: list[c_pe.IMAGE_IMPORT_DESCRIPTOR] = []
        self.import_data = bytearray()

        for name, module in self.imports.items():
            # Take note of the current offset to store the modulename
            name_offset = len(self.import_data)
            self.import_data += name.encode() + b"\x00"

            # Build the module imports and get the RVA of the first thunk to generate an import descriptor
            first_thunk_rva = self._build_module_imports(functions=module.functions)
            import_descriptor = self._build_import_descriptor(
                first_thunk_rva=first_thunk_rva,
                name_rva=self.image_size + name_offset,
            )
            import_descriptors.append(import_descriptor)

        datadirectory_size = 0

        # Take note of the RVA of the first import descriptor
        import_rva = self.image_size + len(self.import_data)
        for descriptor in import_descriptors:
            self.import_data += descriptor.dumps()
            datadirectory_size += len(descriptor)

        # Create a new section
        section_data = utils.align_data(data=self.import_data, blocksize=self.pe.file_alignment)
        size = len(self.import_data) + c_pe.IMAGE_SECTION_HEADER.size
        self.pe.add_section(
            name=".idata",
            data=section_data,
            datadirectory=c_pe.IMAGE_DIRECTORY_ENTRY_IMPORT,
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
        _hint_struct = create_struct("<H")
        for idx, function in enumerate(functions):
            function_offsets.append(len(self.import_data))
            self.import_data += _hint_struct.pack(idx)  # Hint
            self.import_data += function.name.encode() + b"\x00"  # Name

        first_thunk_rva = self.image_size + len(self.import_data)

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

        packing = "<Q" if self.pe.file_header.Machine == c_pe.MachineType.IMAGE_FILE_MACHINE_AMD64 else "<L"
        _struct = create_struct(packing)

        thunkdata: list[bytes] = []
        thunkdata.extend(_struct.pack(rva + self.image_size) for rva in import_rvas)
        thunkdata.append(_struct.pack(0))

        output = b"".join(thunkdata)

        self.thunks.append(self._thunk_data(output))

        return output

    def _build_import_descriptor(self, first_thunk_rva: int, name_rva: int) -> c_pe.IMAGE_IMPORT_DESCRIPTOR:
        """Function to build the import descriptor for the new import table.

        Args:
            first_thunk_rva: The relative address of the first piece of thunkdata.

        Returns:
            The image import descriptor as a `cstruct` object.
        """

        new_import_descriptor = c_pe.IMAGE_IMPORT_DESCRIPTOR()

        new_import_descriptor.OriginalFirstThunk = first_thunk_rva
        new_import_descriptor.TimeDateStamp = 0
        new_import_descriptor.ForwarderChain = 0
        new_import_descriptor.Name = name_rva
        new_import_descriptor.FirstThunk = first_thunk_rva

        return new_import_descriptor
