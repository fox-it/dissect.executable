from __future__ import annotations

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_com_descriptor() -> None:
    """Test the COM descriptor directory."""
    with absolute_path("_data/pe/32/Microsoft.Windows.SoftwareLogo.Binscope.resources.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"

        assert pe.com_descriptor
        assert len(pe.com_descriptor.metadata.streams) == 4
        assert [stream.name for stream in pe.com_descriptor.metadata.streams] == ["#~", "#Strings", "#US", "#GUID"]
