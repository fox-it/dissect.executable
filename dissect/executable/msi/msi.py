from __future__ import annotations
import struct
from dissect.ole import OLE
from dissect.ole.ole import DirectoryEntry
from dissect.ole.exceptions import NotFoundError
from dissect.executable.exception import InvalidDataType, InvalidStringData, InvalidTable
from dissect.executable.msi.c_msi import c_msi
from typing import BinaryIO, Generator
from dissect.ole.c_ole import STGTY
import os

def to_str(bytes_content: bytes) -> str:
    return str(bytes_content, 'utf-8')

class MSI(OLE):
    def __init__(self, fh: BinaryIO) -> None:
        OLE.__init__(self, fh)
        self.StringPool = None
        self.StringData = None
        self.codepage: int = 0
        self.strings: list[list[bytes, int, int]] = [[b'', 0, 0]] # the string at idx 0 is an empty string
        self.n_strings: int = 0
        self._tablecache = {}

    # from https://github.com/ironfede/openmcdf/issues/11
    # MSI stores multiple characters in one unicode code point
    # this function decodes all these directory names to get the actual directory names
    # with the funcionts get, listdir and dirlist from OLE, it will parse the all directory entries from root and save it in self._dirlist
    # it will always only fill _dirlist once, using listdir
    # with these function overloads, first MSI.listdir will be called, and after the directory names will be decrypted
    def listdir(self) -> dict[str, DirectoryEntry]:
        if self._dirlist:
            return OLE.listdir(self)
        OLE.listdir(self)
        self._decode_directory_entry_names()
        return self._dirlist

    dirlist = listdir

    def _msi_base64_encode(self, byte: int) -> int:
        # 0x00-0x3F (0-63) are converted to '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._'
        # all other values higher than 0x3F are converted to '_'
        base64_str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
        if byte < len(base64_str):
            return ord(base64_str[byte])
        return ord('_')

    def _decode_name(self, dir_entry: DirectoryEntry) -> tuple[str, int]:
        len = 0
        output = ""
        for char in dir_entry.entry._ab:
            char = ord(char)
            if ((char >= 0x3800) and (char <= 0x4840)) :
                if (char >= 0x4800): # 0x4800 - 0x483F -> decode only one character
                    char = self._msi_base64_encode(char - 0x4800)
                else: # 0x3800 - 0x383F -> decode two characters
                    char -= 0x3800
                    output += chr(self._msi_base64_encode(char & 0x3f))
                    len += 1
                    char = self._msi_base64_encode((char >> 6) & 0x3f)
            # characters < 0x3800 or > 0x4840 will be saved without any decoding
            output += chr(char)
            len += 1
        return output.rstrip('\x00'), len

    def _decode_directory_entry_names(self) -> None:
        old_dir_list = self._dirlist.copy()
        for old_name in old_dir_list:
            dir_entry = self._dirlist[old_name]
            decoded_name, len = self._decode_name(dir_entry)
            # update directory entry
            dir_entry.name = decoded_name
            dir_entry.entry._ab = decoded_name
            dir_entry.entry._cb = len
            self._dirlist[old_name].entry = dir_entry
            # update _dirlist: key (name) and del old key
            self._dirlist[decoded_name] = self._dirlist.pop(old_name)

    def _valid_codepage(self, codepage: int) -> bool:
        if codepage in [c_msi.CP_ACP, 37, 424, 437, 500, 737, 775, 850, 852, 855, 856, 857, 860, 861, 862, 863, 864, 865, 866, 869, 874, 875,
                  878, 932, 936, 949, 950, 1006, 1026, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258, 1361, 10000, 10006,
                  10007, 10029, 10079, 10081, 20127, 20866, 20932, 21866, 28591, 28592, 28593, 28594, 28595, 28596, 28597, 28598,
                  28599, 28600, 28603, 28604, 28605, 28606, 65000, 65001]:
            return True
        return False

    def _read_content_from_stream(self, name: str) -> bytes:
        # call OLE get function
        dir = self.get(name)
        # if the error is returned
        if isinstance(dir, NotFoundError):
            # try with extra _ in front
            dir = self.get("_" + name)
            if isinstance(dir, NotFoundError):
                # assume the table is empty if dissect.OLE didn't parse directory entry, but it is in __Tables table
                for row in self.get_table("_Tables").rows():
                    if name == to_str(row._cells["Name"]):
                        return b''
                raise NotFoundError(f"directory entry not found: {name}")
        stream = dir.open()
        if stream is None:
            InvalidTable(f"Cannot read from table: {name}")
        content = stream.read()
        return content
    
    def _load_string_table(self) -> None:
        try:
            self.StringPool = self._read_content_from_stream(c_msi.TABLENAME_STRINGPOOL)
            self.StringData = self._read_content_from_stream(c_msi.TABLENAME_STRINGDATA)
        except NotFoundError:
            raise InvalidStringData("error reading string data")
        size = len(self.StringPool)
        if size <= 4:
            raise InvalidStringData("no string data available")
        # there is always 4 bytes per string needed
        count = int(size / 4)
        # make string pool from little to big endian
        self.StringPool = struct.unpack(f"<{len(self.StringPool)//2}H", self.StringPool)
        # the first 4 bytes are for defining the codepage
        self.codepage = self.StringPool[0] | ((self.StringPool[1] & ~0x8000) << 16)
        if self._valid_codepage(self.codepage) == False:
            raise InvalidStringData("invalid codepage")
        idx_strpool = 2
        count -= 1
        offset = 0
        extra_length = 0
        for _ in range(count):
            length = self.StringPool[idx_strpool]
            # if the string length is more than 65535, previous string is 0 and high word of length is in refs field
            # empty strings, that do have an idx, have a length of 0 and a refs of 0
            if extra_length:
                length = (extra_length << 16) + length
                extra_length = 0
            if (offset + length) > len(self.StringData):
                raise InvalidStringData("error reading string information, invalid data")
            refs = self.StringPool[idx_strpool + 1]
            idx_strpool += 2
            # only if length is 0 and refs contains information, it is not an empty string
            if length == 0 and refs != 0:
                extra_length = refs
                continue
            str = self.StringData[offset:offset + length]
            offset += length
            self.strings.append([str, length, refs])
        if (offset != len(self.StringData)):
            raise InvalidStringData("error reading string information, invalid data (not everything is read)")
        self.n_strings = len(self.strings)

    def _msitype_is_binary(self, datatype: int) -> bool:
        if ((datatype) & ~c_msi.MSITYPE_NULLABLE) == (c_msi.MSITYPE_STRING | c_msi.MSITYPE_VALID):
            return True
        return False

    # see bytes_per_column() function here https://github.com/GNOME/msitools/blob/master/libmsi/table.c
    def _bytes_per_cell(self, datatype: int) -> int:
        if self._msitype_is_binary(datatype):
            return 2
        if datatype & c_msi.MSITYPE_STRING:
            return 2
        elif (datatype & 0xFF) <= 2:
            return 2
        elif (datatype & 0xFF) != 4:
            raise InvalidDataType("invalid datatype")
        return 4

    def _get_str(self, idx: int) -> bytes:
        if idx < 0 or idx > self.n_strings:
            IndexError(f"invalid index for strings table: {idx}")
        # idx 0 is an empty string
        # idx starts at 1 -> idx -1 to get the correct string and [0] to get the string value
        return self.strings[idx][0]

    def _read_table(self, table: Table) -> None:
        # size of row = n of cols * size of one cell
        row_size = 0
        for col in range(table.n_cols):
            row_size += self._bytes_per_cell(table.columns[col].type)
        table.rawdata = self._read_content_from_stream(table.name)
        table.rawsize = len(table.rawdata)
        if table.rawsize % row_size:
            raise InvalidTable("table size invalid")
        table.n_rows = int(table.rawsize / row_size)
        offset = 0
        for i in range(table.n_cols):
            bytes_per_cell = self._bytes_per_cell(table.columns[i].type)
            for _ in range(table.n_rows):
                value = table.rawdata[offset : offset + bytes_per_cell]
                if bytes_per_cell == 2:
                    value = struct.unpack('<H', value)[0]
                elif bytes_per_cell == 4:
                    value = struct.unpack('<I', value)[0]
                if table.columns[i].type & c_msi.MSITYPE_STRING:
                    value = self._get_str(value)
                else:
                    value = int(value) - (1 << 15)
                table.columns[i].cells.append(value)
                offset += bytes_per_cell

    def _load_table(self, name: str) -> Table:
        # initiate the table if it is not already in the cache
        try:
            return self._tablecache[name]
        except KeyError:
            t = Table(name, self)
        # in order load a table, init columns based on column information for the table
        t._init_columns()
        # if there are no columns, the table is invalid, assuming that also empty tables have columns
        if t.n_cols == 0:
            raise InvalidTable("table and columns not found")
        # then read in all the cells
        self._read_table(t)
        self._tablecache[name] = t
        return t

    # the required tables to build up all database tables
    # they have double underscores, or single:
    # __StringPool
    # __StringData
    # __Validation
    # __Columns
    # __Tables
    def get_table(self, name: str) -> Table:
        try:
            return self._tablecache[name]
        except KeyError: # if the table doesn't exist yet, load the table
            # in order to load a table, first load the information on strings
            if self.n_strings == 0:
                self._load_string_table()
            # next the __Columns table needs to be loaded
            columns_table = self._load_table(c_msi.TABLENAME_COLUMNS)
            # return if there was an error loading the table, or the columns table was asked for
            if name == c_msi.TABLENAME_COLUMNS:
                return columns_table
            # then load the table asked for
            table = self._load_table(name)
            return table

    def get_tables(self) -> Generator[Table, None, None]:
        tables_table = self.get_table("_Tables")
        for row in tables_table.rows():
            yield(self.get_table(to_str(row._cells["Name"])))

    def dump_stream(self, name: str) -> None:
        # create output directory
        output_dir = "./output"
        # only create the output directory if it doesn't already exists
        os.makedirs(output_dir, exist_ok=True)
        dir_entry = self.get(name)
        if isinstance(dir_entry, NotFoundError):
            raise NotFoundError(f"directory entry not found: {name}")
        # only read and write stream directory entries
        if dir_entry.type == STGTY.STGTY_STREAM:
            content = self._read_content_from_stream(name)
            file_path = os.path.join(output_dir, f"{name}")
            with open(file_path, "wb") as file:
                file.write(content)

    def dump_streams(self) -> None:
        # loop over directory entries
        for dir_name in self.listdir():
            self.dump_stream(dir_name)

class Table():
    # table only holds columns, rows can be created when looping over columns
    def __init__(self, name: str, msi: MSI) -> None:
        self.msi = msi
        self.name = name
        self.columns = {}
        self.n_cols = 0
        self.n_rows = 0
        self._init_columns()

    # the __Columns and also the __Tables tables have pre-defined column information
    # for the rest of the tables, column info is defined in the __Columns table
    def _init_columns(self) -> None:
        if (self.name == c_msi.TABLENAME_COLUMNS):
            self.columns[0] = Column(self, 1, b'Table', c_msi.MSITYPE_VALID | c_msi.MSITYPE_STRING | c_msi.MSITYPE_KEY | 64)
            self.columns[1] = Column(self, 2, b'Number', c_msi.MSITYPE_VALID | c_msi.MSITYPE_KEY | 2)
            self.columns[2] = Column(self, 3, b'Name', c_msi.MSITYPE_VALID | c_msi.MSITYPE_STRING | 64)
            self.columns[3] = Column(self, 4, b'Type', c_msi.MSITYPE_VALID | 2)
        elif (self.name == c_msi.TABLENAME_TABLE):
            self.columns[0] = Column(self, 1, b'Name', c_msi.MSITYPE_VALID | c_msi.MSITYPE_STRING | c_msi.MSITYPE_KEY | 64)
        else:
            columns_table = self.msi.get_table(c_msi.TABLENAME_COLUMNS)
            i = 0
            for row in columns_table.rows():
                if to_str(row._cells["Table"]) == self.name:
                    self.columns[i] = Column(self, row._cells["Number"], row._cells["Name"], row._cells["Type"])
                    i += 1
        self.n_cols = len(self.columns)
        if self.n_cols == 0:
            InvalidTable(f"no columns found, table not valid: {self.name}")

    def rows(self) -> Generator[Row, None, None]:
        for row_number in range(self.n_rows):
            yield Row(self, self.n_cols, row_number)

    def __repr__(self) -> str:
        return f"<Table name={self.name} number of columns={self.n_cols} number of rows={self.n_rows}>"

class Row():
    def __init__(self, table: Table, n_cols: int, row_number: int) -> None:
        self._table = table
        self._table_name = table.name
        self._cells = {}
        self._n_cols = n_cols
        # yield row cells by going over columns
        for key in table.columns:
            col = table.columns[key]
            if isinstance(col.name, str) is False:
                col.name = to_str(col.name)
            # rows are a dictionary of column names and values
            self._cells.update({col.name: col.cells[row_number]})
    
    def __repr__(self) -> str:
        values = " ".join([f"{key}={value!r}" for key, value in self._cells.items()])
        return f"<Row table={self._table_name} {values}>"

class Column():
    def __init__(self, table: Table, number: int, name: bytes, datatype: int):
        self._table = table
        self._table_name = table.name
        self.number = number
        self.name = name
        self.type = datatype
        self.cells = []

    def __repr__(self) -> str:
        return f"<Column table={self._table_name} number={self.number} name={self.name} type={self.type}"
