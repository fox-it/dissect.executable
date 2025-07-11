from __future__ import annotations

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_iat() -> None:
    """Test the IAT directory."""
    with absolute_path("_data/pe/32/NetDbgTLLoc.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"
        assert len(pe.iat) == 24
        assert list(pe.iat) == [
            0x7C811476,
            0x7C80AA66,
            0x7C80AC28,
            0x7C801D77,
            0x7C809FA1,
            0x7C91188A,
            0x7C809794,
            0x7C80994E,
            0x7C809737,
            0x7C8092AC,
            0x7C80A417,
            0x7C859B5C,
            0x7C8017E5,
            0x0,
            0x7C360951,
            0x7C342151,
            0x7C341CBE,
            0x7C3416E9,
            0x7C38C940,
            0x7C34C45B,
            0x7C34240D,
            0x7C34C095,
            0x7C341D5F,
            0x0,
        ]
