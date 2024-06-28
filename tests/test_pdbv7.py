# External dependencies
from dissect.cstruct import cstruct

from dissect.executable.pdb import PDB

c_def = """
typedef long HRESULT;
typedef WCHAR PWSTR;

typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

enum enum_uint16_t : uint16_t {
    a = 0x0,
    b = 0xFF,
};

enum enum_int : int {
    c = 0x0,
    d = 0xFFFF,
};

enum enum_int64 : int64_t {
    e = 0x0,
    f = 0xFFFFFFFF,
};

struct _enum_structure {
    char datatype_char;
    enum_uint16_t datatype_enum_uint16_t;
    enum_int datatype_enum_int;
    enum_int64 datatype_enum_int64_t;
    HRESULT datatype_HRESULT;
} enum_structure;

// Structure containing a struct
struct _struct_structure {
    char datatype_char;
    _enum_structure datatype_enumstruct;
    UNICODE_STRING datatype_unicodestring;
    __int64 datatype_int64;
} struct_structure;

// Structure containing an enum and a struct
struct _enum_and_struct_structure {
    char datatype_char;
    _enum_structure datatype_enum_struct;
    _struct_structure datatype_struct_struct;
    LONGLONG datatype_LONGLONG;
} enum_and_struct_struct;
"""

test_typedefs = cstruct()
test_typedefs = test_typedefs.load(c_def, align=True)


def test_valid_pdb7header():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    assert pdb_file.header.signature == b"Microsoft C/C++ MSF 7.00\r\n\x1ADS\x00\x00\x00"


def test_invalid_pdb7header():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    assert pdb_file.header.signature != b"Microsoft C/C++ MSF 7.00\r\nblah\x00\x00\x00"


def test_pdb7_pagestreams_count():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    assert pdb_file.pdb.root.dStreams == 110
    assert len(pdb_file.pdb.streams) == pdb_file.pdb.root.dStreams


def test_pdb7_dbi_machinetype():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    assert pdb_file.pdb.dbi.header.wMachine == 0x8664


def test_pdb7_dbi_symbol_records_index():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    assert pdb_file.pdb.dbi.header.snSymRecs == 0x67


def test_pdb7_dbi_symbol_info():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    symbols = pdb_file.pdb.symbols

    assert len(symbols) == 1890
    assert symbols["std::memory_order_relaxed"].type_index == 0x159F


def test_pdb7_dbi_module_info():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")

    assert len(pdb_file.pdb.dbi.module_info_list) == 52

    first_object_name = pdb_file.pdb.dbi.module_info_list[0].object_name
    assert first_object_name == b"C:\\Users\\user\\source\\repos\\dissect.pdb\\dissect.pdb\\x64\\Debug\\dissect.pdb.obj"

    last_object_name = pdb_file.pdb.dbi.module_info_list[-2].object_name
    assert last_object_name == b"C:\\Program Files (x86)\\Windows Kits\\10\\lib\\10.0.22621.0\\ucrt\\x64\\ucrtd.lib"


def test_pdb7_tpistream_pagesize():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    tpi_stream = pdb_file.pdb.streams[2]
    tpi_stream.page_size == 0x1000


def test_pdb7_pdb_cstruct_typedefs():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    pdb_cstruct = pdb_file.pdb.typedefs

    assert len(pdb_cstruct.typedefs) == 545
    assert "simple_datatypes_struct" in pdb_cstruct.typedefs
    assert "windows_datatypes_struct" in pdb_cstruct.typedefs


def test_pdb7_pdb_cstruct_names():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    pdb_cstruct = pdb_file.pdb.typedefs

    test_struct_struct_names = [i.name for i in test_typedefs.typedefs["_struct_structure"].fields]
    pdb_struct_struct_names = [i.name for i in pdb_cstruct.typedefs["_struct_structure"].fields]
    assert test_struct_struct_names == pdb_struct_struct_names


def test_pdb7_pdb_cstruct_parsing():
    pdb_file = PDB(pdb_file="tests/data/testpdb_x64.pdb")
    pdb_cstruct = pdb_file.pdb.typedefs

    test_enum_structure = pdb_cstruct._enum_structure(
        b"\x02\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04"
    )
    assert test_enum_structure.datatype_char == b"\x02"
    assert test_enum_structure.datatype_HRESULT == 0x4030201
