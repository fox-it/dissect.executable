from __future__ import annotations

import datetime

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_bound_import() -> None:
    """Test the bound imports directory."""
    with absolute_path("_data/pe/32/NetDbgTLLoc.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"
        assert len(pe.bound_import) == 2
        assert list(pe.bound_import)

        assert pe.bound_import[0].name == "KERNEL32.dll"
        assert len(pe.bound_import[0].forwarders) == 1
        assert pe.bound_import[0].forwarders[0].name == "NTDLL.DLL"

        assert pe.bound_import["MSVCR71.dll"].timestamp == datetime.datetime(
            2003, 2, 21, 12, 42, 20, tzinfo=datetime.timezone.utc
        )
