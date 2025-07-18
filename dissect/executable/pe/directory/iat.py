from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    from collections.abc import Iterator


class IatDirectory(DataDirectory):
    """The import address table (IAT) directory of a PE file."""

    def __repr__(self) -> str:
        return f"<IatDirectory entries={len(self.entries)}>"

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[int]:
        return iter(self.entries)

    def __getitem__(self, idx: int) -> int:
        return self.entries[idx]

    @cached_property
    def entries(self) -> list[int]:
        """List of addresses in the import address table."""
        self.pe.vfh.seek(self.address)
        ctype = c_pe.ULONGLONG if self.pe.is_64bit() else c_pe.ULONG
        return ctype[self.size // len(ctype)](self.pe.vfh)
