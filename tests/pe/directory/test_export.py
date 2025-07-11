from __future__ import annotations

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_export() -> None:
    """Test the export directory."""
    with absolute_path("_data/pe/32/NetDbgTLLoc.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"
        assert pe.exports
        assert len(list(pe.exports)) == 2

        assert pe.exports.name == "NatDbgTLLoc.dll"
        assert pe.exports[1].ordinal == 1
        assert pe.exports[1].name == "OSDebug4VersionCheck"
        assert pe.exports[1].address == 0x10DD
        assert pe.exports[2].ordinal == 2
        assert pe.exports[2].name == "TLFunc"
        assert pe.exports[2].address == 0x1590

        assert pe.exports["OSDebug4VersionCheck"].ordinal == 1
        assert pe.exports["TLFunc"].ordinal == 2
