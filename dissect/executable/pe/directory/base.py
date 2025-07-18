from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.executable.pe.pe import PE


class DataDirectory:
    """Base class for PE data directories."""

    def __init__(self, pe: PE, address: int, size: int):
        self.pe = pe
        self.address = address
        self.size = size

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} address={self.address:#x} size={self.size}>"
