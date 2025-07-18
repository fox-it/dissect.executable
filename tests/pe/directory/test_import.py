from __future__ import annotations

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_import() -> None:
    """Test the import directory."""
    with absolute_path("_data/pe/32/OLEACCHOOKS.DLL").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"
        assert len(pe.imports) == 12
        assert list(pe.imports)

        assert pe.imports[0].name == "msvcrt.dll"
        assert pe.imports["msvcrt.dll"] == pe.imports[0]
        assert len(list(pe.imports[0])) == 7

        assert pe.imports[0].functions[0].name == "_vsnwprintf"
        assert pe.imports[0].functions[0].ordinal == 1004

        assert pe.imports[0]["_vsnwprintf"] == pe.imports[0].functions[0]
        assert pe.imports[0][1004] == pe.imports[0].functions[0]
