from io import BytesIO

import pytest

from dissect.executable.exception import InvalidPE
from dissect.executable.pe.pe import PE


def test_pe_valid_signature():
    with open("tests/data/testexe.exe", "rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert pe._valid() is True


def test_pe_invalid_signature():
    with pytest.raises(InvalidPE):
        PE(BytesIO(b"MZ" + b"\x00" * 400))


def test_pe_sections():
    known_sections = [".dissect", ".text", ".rdata", ".idata", ".rsrc", ".reloc", ".tls"]
    with open("tests/data/testexe.exe", "rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert known_sections == [section for section in pe.sections.keys()]


def test_pe_imports():
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
    with open("tests/data/testexe.exe", "rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert known_imports == [import_ for import_ in pe.imports.keys()]


def test_pe_exports():
    # Too much export functions to put in a list
    known_exports = ["1", "2", "CreateOverlayApiInterface", "CreateShadowPlayApiInterface", "ShadowPlayOnSystemStart"]

    with open("tests/data/testexe.exe", "rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert known_exports == [export_ for export_ in pe.exports.keys()]


def test_pe_resources():
    known_resource_types = ["RcData", "Manifest"]
    with open("tests/data/testexe.exe", "rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert known_resource_types == [resource for resource in pe.resources.keys()]


def test_pe_relocations():
    with open("tests/data/testexe.exe", "rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert len(pe.relocations) == 9


def test_pe_tls_callbacks():
    known_callbacks = [430080, 434176, 438272, 442368, 446464, 450560, 454656, 458752, 462848, 466944]

    with open("tests/data/testexe.exe", "rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

    assert pe.tls_callbacks == known_callbacks
