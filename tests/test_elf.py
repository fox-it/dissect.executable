from __future__ import annotations

from io import BytesIO

import pytest

from dissect.executable import ELF
from dissect.executable.exception import InvalidSignatureError


def test_elf_invalid_signature() -> None:
    with pytest.raises(InvalidSignatureError):
        ELF(BytesIO(b"\x20ELF" + b"\x00" * 0x40))


def test_elf_valid_signature() -> None:
    ELF(BytesIO(b"\x7fELF" + b"\x00" * 0x40))
