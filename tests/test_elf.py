from io import BytesIO

import pytest

from dissect.executable import ELF
from dissect.executable.exception import InvalidSignatureError


def test_elf_invalid_signature():
    with pytest.raises(InvalidSignatureError):
        ELF(BytesIO(b"\x20ELF" + b"\x00" * 0x40))


def test_elf_valid_signature():
    ELF(BytesIO(b"\x7FELF" + b"\x00" * 0x40))
