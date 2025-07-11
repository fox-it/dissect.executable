# Most test data is from:
# - https://github.com/cubiclesoft/windows-pe-artifact-library

from __future__ import annotations

import datetime
from io import BytesIO

import pytest

from dissect.executable.exception import InvalidSignatureError
from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_pe_invalid_signature() -> None:
    with pytest.raises(InvalidSignatureError):
        PE(BytesIO(b"MZ" + b"\x00" * 400))


def test_pe_basic() -> None:
    """Test basic properties of a PE file."""
    with absolute_path("_data/pe/64/test.exe").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert not pe.is_os2()
        assert pe.is_64bit()
        assert not pe.is_reproducible()

        assert pe.timestamp == datetime.datetime(2024, 3, 8, 8, 6, 29, tzinfo=datetime.timezone.utc)


def test_pe_sections() -> None:
    """Test that the PE file has the expected sections."""
    with absolute_path("_data/pe/64/test.exe").open("rb") as fh:
        pe = PE(fh)

        assert [section.name for section in pe.sections] == [
            ".dissect",
            ".text",
            ".rdata",
            ".idata",
            ".rsrc",
            ".reloc",
            ".tls",
        ]


def test_pe_os2() -> None:
    """Test an OS/2 executable."""
    with absolute_path("_data/pe/16/DPMIRES.EXE").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_os2()
        assert not pe.is_pe()
