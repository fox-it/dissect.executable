from __future__ import annotations

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_exception() -> None:
    """Test the exception directory."""
    with absolute_path("_data/pe/32/PUNZIP.EXE").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "R4000"
        assert len(pe.exceptions) == 172
        assert list(pe.exceptions)

        assert pe.exceptions[0].BeginAddress == 0x11010
        assert pe.exceptions[0].EndAddress == 0x11068
