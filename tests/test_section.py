from __future__ import annotations

from io import BytesIO
from unittest.mock import Mock, patch

import pytest

from dissect.executable.elf.c_elf import SHN
from dissect.executable.elf.elf import (
    SectionTable,
    StringTable,
    Symbol,
    SymbolTable,
    c_elf_64,
)


@pytest.fixture
def section_table(entries: int) -> SectionTable:
    """Creates a SectionTable without a StringTable attached to it."""
    elf = Mock()
    elf.header.e_shnum = entries
    elf.header.e_shstrndx = None
    return SectionTable.from_elf(elf)


def mock_section_table(section_data: bytes) -> Mock:
    shdr = c_elf_64.Shdr(sh_offset=len(c_elf_64.Shdr), sh_size=len(section_data), sh_entsize=len(section_data))
    mocked_table = Mock()
    mocked_table.fh = BytesIO(shdr.dumps() + section_data)
    mocked_table.offset = 0
    mocked_table.size = 0
    mocked_table.c_elf = c_elf_64
    return mocked_table


@pytest.mark.parametrize("entries", [0])
def test_section_unknown_index(section_table: SectionTable) -> None:
    with pytest.raises(IndexError):
        assert section_table[1]


@pytest.mark.parametrize("entries", [20])
def test_section_selector(section_table: SectionTable, entries: int) -> None:
    with patch.object(SectionTable, "_create_item") as mocked_section:
        assert section_table.items == [None] * entries
        assert section_table[0] == mocked_section.return_value
        assert section_table[1:] == [None] * (entries - 1)
        assert list(section_table) == [mocked_section.return_value] * entries


def test_string_table() -> None:
    STRING_TABLE = b"\x00hello\x00world\x00"

    mocked_table = mock_section_table(STRING_TABLE)

    string_table = StringTable.from_section_table(mocked_table, 0)
    assert string_table[0] is None
    assert string_table[1] == "hello"
    assert string_table[2] == "ello"
    assert string_table[7] == "world"


def test_symboltable() -> None:
    mocked_table = mock_section_table(b"hello")
    with patch.object(Symbol, "from_symbol_table") as mocked_symbol:
        symbol_table = SymbolTable.from_section_table(mocked_table, 0)
        assert symbol_table[0] == mocked_symbol.return_value


def test_table_symbol_creation() -> None:
    symbol_bytes = c_elf_64.Sym().dumps()

    mocked_table = mock_section_table(symbol_bytes)

    symbol_table = SymbolTable.from_section_table(mocked_table, 0)
    symbol_table._link = [".hello"]

    symbol = symbol_table[0]

    # Test empty symbol
    assert symbol.bind == c_elf_64.STB.LOCAL
    assert symbol.type == c_elf_64.STT.NOTYPE
    assert symbol.visibility == c_elf_64.STV.DEFAULT
    assert symbol.value == 0
    assert symbol.name == ".hello"


def test_symboltable_filter() -> None:
    symbol_bytes = c_elf_64.Sym(st_info=0x16).dumps()

    mocked_table = mock_section_table(symbol_bytes)

    symbol_table = SymbolTable.from_section_table(mocked_table, 0)
    symbol_table._link = [".hello"]

    symbols = symbol_table.find(lambda x: x.bind == c_elf_64.STB.GLOBAL)
    assert len(symbols) == 1
    assert symbols[0].name == ".hello"
    assert len(symbol_table.find(lambda x: x.name == ".hello")) == 1


@pytest.mark.parametrize(
    ("section_index", "value", "expected_output"),
    [
        ("UNDEF", 100, 0),
        ("ABS", 100, 100),
        ("COMMON", 100, 100),
    ],
)
def test_symbol_value(section_index: str, value: int, expected_output: int) -> None:
    symbol_bytes = c_elf_64.Sym(st_value=value, st_shndx=c_elf_64.SHN[section_index].value).dumps()

    symbol = Symbol(BytesIO(symbol_bytes), 0, c_elf_64)
    assert symbol.value == expected_output


@pytest.mark.parametrize(
    ("section_index", "table_offset", "expected_output"),
    [
        (SHN.UNDEF.value, 100, 0),
        (SHN.ABS.value, 100, 0),
        (20, 100, 100),
    ],
)
def test_symbol_value_from_shndex(section_index: int, table_offset: int, expected_output: int) -> None:
    symbol_bytes = c_elf_64.Sym(st_shndx=section_index).dumps()

    symbol = Symbol(BytesIO(symbol_bytes), 0, c_elf_64)
    mock = [Mock(offset=table_offset)] * (symbol.symbol.st_shndx + 1)
    assert symbol.value_based_on_shndx(mock) == expected_output
