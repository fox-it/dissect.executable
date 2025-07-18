from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    from collections.abc import Iterator


class TlsDirectory(DataDirectory):
    """The TLS (Thread Local Storage) directory of a PE file."""

    def __repr__(self) -> str:
        return f"<TlsDirectory callbacks={len(self.callbacks)}>"

    def __len__(self) -> int:
        return len(self.callbacks)

    def __iter__(self) -> Iterator[int]:
        return iter(self.callbacks)

    def __getitem__(self, idx: int) -> int:
        return self.callbacks[idx]

    @cached_property
    def header(self) -> c_pe.IMAGE_TLS_DIRECTORY32 | c_pe.IMAGE_TLS_DIRECTORY64:
        """The TLS directory header."""
        self.pe.vfh.seek(self.address)
        ctype = c_pe.IMAGE_TLS_DIRECTORY64 if self.pe.is_64bit() else c_pe.IMAGE_TLS_DIRECTORY32
        return ctype(self.pe.vfh)

    @cached_property
    def callbacks(self) -> list[int]:
        """List of callback addresses."""
        if not self.header.AddressOfCallBacks:
            return []

        self.pe.vfh.seek(self.pe.va_to_rva(self.header.AddressOfCallBacks))
        ctype = c_pe.ULONGLONG if self.pe.is_64bit() else c_pe.ULONG
        try:
            return ctype[None](self.pe.vfh)
        except EOFError:
            return []
