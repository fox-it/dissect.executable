from __future__ import annotations

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_basereloc() -> None:
    """Test the base relocations directory."""
    with absolute_path("_data/pe/32/PUNZIP.EXE").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "R4000"
        assert len(pe.base_relocations) == 5454
        assert list(pe.base_relocations)

        assert pe.base_relocations[0].rva == 0x102C
        assert pe.base_relocations[0].type == c_pe.IMAGE_REL_BASED.MIPS_JMPADDR
