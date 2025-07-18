from __future__ import annotations

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_debug_codeview() -> None:
    """Test the CodeView debug entry."""
    with absolute_path("_data/pe/32/NetDbgTLLoc.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"

        assert pe.debug
        assert len(pe.debug) == 2

        assert pe.debug[0].type.name == "CODEVIEW"
        assert str(pe.debug[0].signature) == "434b5c0d-1ee4-4bc8-bdf0-2e87ea897763"
        assert pe.debug[0].age == 2
        assert pe.debug[0].pdb == "I:\\VS70Builds\\3077\\vsbuilt\\retail\\Bin\\i386\\opt\\natdbgtlloc.pdb"

        assert pe.pdb_path() == "I:\\VS70Builds\\3077\\vsbuilt\\retail\\Bin\\i386\\opt\\natdbgtlloc.pdb"


def test_debug_vc_feature() -> None:
    """Test the VC feature debug entry."""
    with absolute_path("_data/pe/32/aborttest.exe").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"

        assert pe.debug
        assert len(pe.debug) == 2

        assert pe.debug[1].type.name == "VC_FEATURE"
        assert pe.debug[1].pre_vc11 == 0
        assert pe.debug[1].ccpp == 23
        assert pe.debug[1].gs == 23
        assert pe.debug[1].sdl == 0
        assert pe.debug[1].guards == 0


def test_debug_pogo() -> None:
    """Test the POGO debug entry."""
    with absolute_path("_data/pe/32/Dummy.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"

        assert pe.debug
        assert len(pe.debug) == 2

        assert pe.debug[0].type.name == "POGO"
        assert len(pe.debug[0]) == 4
        assert list(pe.debug[0]) == [
            (4096, 56, ".rdata"),
            (4152, 120, ".rdata$zzzdbg"),
            (8192, 96, ".rsrc$01"),
            (8288, 928, ".rsrc$02"),
        ]


def test_debug_repro() -> None:
    """Test the REPRO debug entry."""
    with absolute_path("_data/pe/32/Dummy.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"

        assert pe.debug
        assert len(pe.debug) == 2

        assert pe.debug[1].type.name == "REPRO"
        assert pe.debug[1].hash.hex() == "884f504ffad2de5c25d4bbddff0f8b1fbaa2c8341f2dbdaff5f181ce1300f2e4"
