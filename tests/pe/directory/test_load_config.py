from __future__ import annotations

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_load_config() -> None:
    """Test the load config directory."""
    with absolute_path("_data/pe/64/comres.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "ARM64"
        assert pe.load_config

        assert pe.load_config.security_cookie == 0x180004000
        assert pe.load_config.guard_flags.name == "CF_INSTRUMENTED"

        assert pe.load_config.chpe.Version == 1
