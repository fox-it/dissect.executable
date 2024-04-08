from io import BytesIO
from typing import BinaryIO, Generator

# External imports
from dissect.cstruct import cstruct

from dissect.executable.pdb.helpers.c_pdb import c_pdb, leaf_translation
from dissect.executable.pdb.helpers.pagestream import PageStream

# Local imports
from dissect.executable.pdb.helpers.utils import retain_file_offset


def parse_userdefined_symbol(symbol_data: BinaryIO) -> cstruct:
    """Parse the symbols for the user defined types.

    The user defined types need to be reparsed from the beginning of the `symbol_data`.

    Args:
        symbol_data: The raw data of the symbol to be parsed.

    Returns:
        The symbol as a `cstruct`.
    """

    symbol_data.seek(0)
    return c_pdb.UserDefinedSymbol(symbol_data)


def parse_constant_symbol(symbol_data: BinaryIO) -> cstruct:
    """Parse the symbols for constant types.

    The constant types are a little bit weird as they're parsed in different ways depending on the value field.

    Args:
        symbol_data: The raw data of the symbol to be parsed.

    Returns:
        The symbol as a `cstruct`.
    """

    header = c_pdb.ConstantSymbolHeader(symbol_data)

    # Define an empty struct for the constant symbol type
    symbol = c_pdb.ConstantSymbol()
    symbol.type_index = header.type_index

    if header.value & 0x8000:
        # Depending on the value this needs to be parsed as a specific data type
        leaf_type = c_pdb.LEAF_ENUM_e(header.value)
        symbol.value = leaf_translation[leaf_type.value](symbol_data)
    else:
        symbol.value = header.value.to_bytes(2, "little")

    symbol.name = c_pdb.char[None](symbol_data)

    return symbol


class DBI:
    """Class for parsing the DBI stream of a PDB file.

    Attributes:
        SYMBOL_STRUCTS: A dictionary containing the different `cstruct` definitions or functions defined for parsing a
        certain symbol type.

    Args:
        streams: The list with `PageStream` entries for this PDB.
    """

    SYMBOL_STRUCTS = {
        # PublicSymbol
        c_pdb.SYM_ENUM_e.S_PUB32: c_pdb.PublicSymbol,
        c_pdb.SYM_ENUM_e.S_PUB32_ST: c_pdb.PublicSymbol_ST,
        # ConstantSymbol
        c_pdb.SYM_ENUM_e.S_CONSTANT: parse_constant_symbol,
        c_pdb.SYM_ENUM_e.S_CONSTANT_ST: parse_constant_symbol,
        # RegisterSymbol
        c_pdb.SYM_ENUM_e.S_REGISTER: c_pdb.RegisterSymbol,
        c_pdb.SYM_ENUM_e.S_REGISTER_ST: c_pdb.RegisterSymbol,
        c_pdb.SYM_ENUM_e.S_MANYREG: None,
        c_pdb.SYM_ENUM_e.S_MANYREG_ST: None,
        c_pdb.SYM_ENUM_e.S_MANYREG2: None,
        c_pdb.SYM_ENUM_e.S_MANYREG2_ST: None,
        # GlobalDataSymbol
        c_pdb.SYM_ENUM_e.S_GDATA32: c_pdb.GlobalDataSymbol,
        c_pdb.SYM_ENUM_e.S_GDATA32_ST: c_pdb.GlobalDataSymbol,
        c_pdb.SYM_ENUM_e.S_GMANDATA: c_pdb.GlobalDataSymbol,
        c_pdb.SYM_ENUM_e.S_GMANDATA_ST: c_pdb.GlobalDataSymbol,
        # ManagedDataSymbol
        c_pdb.SYM_ENUM_e.S_LDATA32: c_pdb.ManagedDataSymbol,
        c_pdb.SYM_ENUM_e.S_LDATA32_ST: c_pdb.ManagedDataSymbol,
        c_pdb.SYM_ENUM_e.S_LMANDATA: c_pdb.ManagedDataSymbol,
        c_pdb.SYM_ENUM_e.S_LMANDATA_ST: c_pdb.ManagedDataSymbol,
        # ProcedureReferenceSymbol
        c_pdb.SYM_ENUM_e.S_PROCREF: c_pdb.ProcedureReferenceSymbol,
        c_pdb.SYM_ENUM_e.S_PROCREF_ST: c_pdb.ProcedureReferenceSymbol,
        c_pdb.SYM_ENUM_e.S_LPROCREF: c_pdb.ProcedureReferenceSymbol,
        c_pdb.SYM_ENUM_e.S_LPROCREF_ST: c_pdb.ProcedureReferenceSymbol,
        # DataReferenceSymbol
        c_pdb.SYM_ENUM_e.S_DATAREF: c_pdb.DataReferenceSymbol,
        c_pdb.SYM_ENUM_e.S_DATAREF_ST: c_pdb.DataReferenceSymbol,
        # AnnotationReferenceSymbol
        c_pdb.SYM_ENUM_e.S_ANNOTATIONREF: c_pdb.AnnotationReferenceSymbol,
        # TrampolineSymbol
        c_pdb.SYM_ENUM_e.S_TRAMPOLINE: c_pdb.TrampolineSymbol,
        # UserDefinedSymbol
        c_pdb.SYM_ENUM_e.S_UDT: parse_userdefined_symbol,
        c_pdb.SYM_ENUM_e.S_UDT_ST: parse_userdefined_symbol,
        # ThreadStorageSymbol
        c_pdb.SYM_ENUM_e.S_GTHREAD32: c_pdb.ThreadStorageSymbol,
        c_pdb.SYM_ENUM_e.S_GTHREAD32_ST: c_pdb.ThreadStorageSymbol,
        c_pdb.SYM_ENUM_e.S_LTHREAD32: c_pdb.ThreadStorageSymbol,
        c_pdb.SYM_ENUM_e.S_LTHREAD32_ST: c_pdb.ThreadStorageSymbol,
        # ProcedureSymbol
        c_pdb.SYM_ENUM_e.S_GPROC32: c_pdb.ProcedureSymbol,
        c_pdb.SYM_ENUM_e.S_GPROC32_ST: c_pdb.ProcedureSymbol,
        c_pdb.SYM_ENUM_e.S_LPROC32: c_pdb.ProcedureSymbol,
        c_pdb.SYM_ENUM_e.S_LPROC32_ST: c_pdb.ProcedureSymbol,
        c_pdb.SYM_ENUM_e.S_LPROC32_DPC: c_pdb.ProcedureSymbol,
        c_pdb.SYM_ENUM_e.S_GPROC32_ID: c_pdb.ProcedureSymbol,
        c_pdb.SYM_ENUM_e.S_LPROC32_ID: c_pdb.ProcedureSymbol,
        c_pdb.SYM_ENUM_e.S_LPROC32_DPC_ID: c_pdb.ProcedureSymbol,
        # TokenReferenceSymbol
        c_pdb.SYM_ENUM_e.S_TOKENREF: c_pdb.TokenReferenceSymbol,
    }

    def __init__(self, streams: list[PageStream]):
        self.stream = streams[3]
        self.header = c_pdb.DbiHeader(self.stream)

        self.symbol_stream = streams[self.header.snSymRecs]
        self.symbols = dict()
        self.module_info_list = []
        self.section_map_items = []

    def parse_info(self):
        """Parse the symbol information that is present within the PDB file."""

        module_info_offset = len(self.header)
        self._parse_module_info(offset=module_info_offset, dbi_stream=self.stream)

        section_map_offset = len(self.header) + self.header.cbGpModi + self.header.cbSC
        self._parse_section_maps(offset=section_map_offset, dbi_stream=self.stream)

        self._parse_symbols()

    def _parse_module_info(self, offset: int, dbi_stream: BinaryIO):
        """Function to parse the module information, this structure contains the module names and objects.

        Args:
            offset: The offset from which to start reading the module information structures.
            dbi_stream: A file-like object of the DBI stream to be parsed.
        """

        dbi_stream.seek(offset)
        module_info_end = offset + self.header.cbGpModi

        offset = dbi_stream.tell()
        while offset < module_info_end:
            if offset % 4 != 0:
                dbi_stream.seek(offset + (4 - (offset % 4)))

            module_info_base = c_pdb.DbiModuleInfoBase(dbi_stream)
            if module_info_base.stream != -1:
                self.module_info_list.append(module_info_base)

            offset = dbi_stream.tell()

    def _parse_section_maps(self, offset: int, dbi_stream: BinaryIO):
        """Function to parse the section maps within a PDB file.

        Args:
            offset: The offset from which to start reading the section maps structures.
            dbi_stream: A file-like object of the DBI stream to be parsed.
        """

        dbi_stream.seek(offset)
        section_map_end = offset + self.header.cbSecMap

        while offset < section_map_end:
            dbi_section_map_item = c_pdb.DbiSectionMapItem(dbi_stream)
            self.section_map_items.append(dbi_section_map_item)

            offset = dbi_stream.tell()

    def _parse_symbols(self) -> dict:
        """Parse the symbols as a dictionary. And set this attribute for the class.

        Returns:
            A `dict` containing of the symbols within the PDB file.
        """

        for symbol in self.parse_symbols():
            if symbol and symbol.name:
                self.symbols[symbol.name.decode()] = symbol

    def parse_symbols(self) -> Generator[cstruct, None, None]:
        """Function to parse the symbols defined in the PDB.

        Yields:
            The symbols that were found as `cstruct` objects.
        """

        offset = self.symbol_stream.tell()
        with retain_file_offset(fobj=self.symbol_stream, offset=offset):
            while True:
                try:
                    # Read the symbol record header to establish the right struct to use
                    symbol_record = c_pdb.SymbolRecordHeader(self.symbol_stream)
                except EOFError:
                    break

                # Read the symbol data, compensate for the length field in the header
                symbol_data = BytesIO(self.symbol_stream.read(symbol_record.length - 2))
                symbol = self.SYMBOL_STRUCTS[symbol_record.type](symbol_data)

                yield symbol
