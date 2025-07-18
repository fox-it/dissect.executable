from __future__ import annotations

import hashlib

from dissect.executable.pe.pe import PE
from tests._utils import absolute_path


def test_security() -> None:
    """Test the security directory."""
    with absolute_path("_data/pe/32/UWPEnum.dll").open("rb") as fh:
        pe = PE(fh)

        assert pe.is_pe()
        assert pe.machine.name == "I386"
        assert pe.security

        assert pe.security[0].revision == 512
        assert pe.security[0].type.name == "PKCS_SIGNED_DATA"
        assert hashlib.sha1(pe.security[0].data).hexdigest() == "933f765d09486cc41091e2bfd305be723e9e4b53"
