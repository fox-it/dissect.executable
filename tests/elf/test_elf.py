from __future__ import annotations

from io import BytesIO

import pytest

from dissect.executable.elf.c_elf import SHT, c_elf_32, c_elf_32_be, c_elf_64, c_elf_64_be
from dissect.executable.elf.elf import ELF
from dissect.executable.exception import InvalidSignatureError


def test_elf_invalid_signature() -> None:
    with pytest.raises(InvalidSignatureError):
        ELF(BytesIO(b"\x20ELF" + b"\x00" * 0x40))


def test_elf_valid_signature() -> None:
    ELF(BytesIO(b"\x7fELF" + b"\x00" * 0x40))


def _make_elf(is_64: bool, is_little: bool) -> bytes:
    """Make a minimal ELF file with a symbol table that has one symbol, named ``symbol`` with a value of 0x1234."""
    c_elf = {
        (False, True): c_elf_32,
        (False, False): c_elf_32_be,
        (True, True): c_elf_64,
        (True, False): c_elf_64_be,
    }[is_64, is_little]

    symtab = c_elf.Sym.dumps(c_elf.Sym()) + c_elf.Sym.dumps(c_elf.Sym(st_name=1, st_shndx=1, st_value=0x1234))
    strtab = b"\x00symbol\x00"
    shstrtab = b"\x00.symtab\x00.strtab\x00.shstrtab\x00"

    # The section data follows the ELF header, and the section headers follow the section data
    data = b""
    headers = [c_elf.Shdr()]
    for name, type_, content, link, entsize in [
        (1, SHT.SYMTAB, symtab, 2, len(c_elf.Sym)),
        (9, SHT.STRTAB, strtab, 0, 0),
        (17, SHT.STRTAB, shstrtab, 0, 0),
    ]:
        offset = len(c_elf.Ehdr) + len(data)
        headers.append(
            c_elf.Shdr(
                sh_name=name, sh_type=type_, sh_offset=offset, sh_size=len(content), sh_link=link, sh_entsize=entsize
            )
        )
        data += content

    header = c_elf.Ehdr(
        e_ident=b"\x7fELF" + bytes([2 if is_64 else 1, 1 if is_little else 2, 1]) + bytes(9),
        e_type=2,
        e_version=1,
        e_shoff=len(c_elf.Ehdr) + len(data),
        e_ehsize=len(c_elf.Ehdr),
        e_shentsize=len(c_elf.Shdr),
        e_shnum=len(headers),
        e_shstrndx=3,
    )
    return c_elf.Ehdr.dumps(header) + data + b"".join(c_elf.Shdr.dumps(shdr) for shdr in headers)


@pytest.mark.parametrize("is_64", [False, True], ids=["32", "64"])
@pytest.mark.parametrize("is_little", [True, False], ids=["little", "big"])
def test_elf_make_endianness(is_64: bool, is_little: bool) -> None:
    """Test whether the ELF files for the other tests are written with the right endianness."""
    # e_type is 2, right after the 16 bytes of e_ident
    assert _make_elf(is_64, is_little)[16:18] == (b"\x02\x00" if is_little else b"\x00\x02")


@pytest.mark.parametrize("is_64", [False, True], ids=["32", "64"])
def test_elf_endianness(is_64: bool) -> None:
    """Test whether ELF files with a different endianness can be open at the same time.

    Entries are read lazily, so opening the big endian file must not change the endianness of the little endian one.
    """
    little = ELF(BytesIO(_make_elf(is_64, is_little=True)))
    big = ELF(BytesIO(_make_elf(is_64, is_little=False)))

    for elf in (little, big):
        assert [section.type for section in elf.sections] == [SHT.NULL, SHT.SYMTAB, SHT.STRTAB, SHT.STRTAB]
        # The name of the null section isn't set
        assert [section.name for section in elf.sections][1:] == [".symtab", ".strtab", ".shstrtab"]

        assert len(elf.symbol_tables) == 1
        symbols = list(elf.symbol_tables[0])
        assert symbols[1].name == "symbol"
        assert symbols[1].value == 0x1234
