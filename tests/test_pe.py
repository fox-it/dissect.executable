from io import BytesIO

import pytest

from dissect.executable.exception import InvalidPE
from dissect.executable.pe.pe import PE

from .util import data_file


def test_pe_valid_signature() -> None:
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert pe._valid() is True


def test_pe_invalid_signature() -> None:
    with pytest.raises(InvalidPE):
        PE(BytesIO(b"MZ" + b"\x00" * 400))


def test_pe_sections() -> None:
    known_sections = [
        ".dissect",
        ".text",
        ".rdata",
        ".idata",
        ".rsrc",
        ".reloc",
        ".tls",
    ]
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert known_sections == list(pe.sections)


def test_pe_imports() -> None:
    known_imports = [
        "SHELL32.dll",
        "ole32.dll",
        "OLEAUT32.dll",
        "ADVAPI32.dll",
        "WTSAPI32.dll",
        "SHLWAPI.dll",
        "VERSION.dll",
        "KERNEL32.dll",
        "USER32.dll",
    ]
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert known_imports == list(pe.imports)


def test_pe_exports() -> None:
    # Too much export functions to put in a list
    known_exports = [
        "1",
        "2",
        "CreateOverlayApiInterface",
        "CreateShadowPlayApiInterface",
        "ShadowPlayOnSystemStart",
    ]

    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert known_exports == list(pe.exports)


def test_pe_resources() -> None:
    known_resource_types = ["RcData", "Manifest"]
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert known_resource_types == list(pe.resources)


def test_pe_relocations() -> None:
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert len(pe.relocations) == 9


def test_pe_tls_callbacks() -> None:
    known_callbacks = [
        430080,
        434176,
        438272,
        442368,
        446464,
        450560,
        454656,
        458752,
        462848,
        466944,
    ]

    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert pe.tls_callbacks == known_callbacks
