from __future__ import annotations

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_delay_import() -> None:
    """Test the delay imports directory."""
    with absolute_path("_data/pe/32/OLEACCHOOKS.DLL").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"
        assert len(pe.delay_import) == 1
        assert list(pe.delay_import)

        assert pe.delay_import[0].name == "USER32.dll"
        assert pe.delay_import["USER32.dll"] == pe.delay_import[0]
        assert len(list(pe.delay_import[0])) == 2

        assert pe.delay_import[0].functions[0].name == "RegisterWindowMessageW"
        assert pe.delay_import[0].functions[0].ordinal == 755
        assert pe.delay_import[0].functions[0].address == 0x10001FBC
        assert pe.delay_import[0].functions[1].name == "CallNextHookEx"
        assert pe.delay_import[0].functions[1].ordinal == 31
        assert pe.delay_import[0].functions[1].address == 0x10001FA1

        assert pe.delay_import[0]["RegisterWindowMessageW"] == pe.delay_import[0].functions[0]
        assert pe.delay_import[0][755] == pe.delay_import[0].functions[0]
