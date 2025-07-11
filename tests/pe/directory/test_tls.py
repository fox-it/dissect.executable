from __future__ import annotations

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_tls() -> None:
    """Test the TLS directory."""
    with absolute_path("_data/pe/32/mingwm10.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"
        assert len(pe.tls) == 2
        assert list(pe.tls) == [0x6FBC1480, 0x6FBC1430]
