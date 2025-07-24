from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING

from dissect.util.ts import from_unix

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator


class ExportDirectory(DataDirectory):
    """The export directory of a PE file."""

    def __repr__(self) -> str:
        return f"<ExportDirectory name={self.name!r} functions={len(self.functions)}>"

    def __iter__(self) -> Iterator[ExportFunction]:
        return iter(self.functions)

    def __getitem__(self, idx: str | int) -> ExportFunction:
        if isinstance(idx, int):
            return self._by_ordinal[idx]
        if isinstance(idx, str):
            if idx not in self._by_name:
                raise KeyError(f"Export function {idx!r} not found in directory {self.name!r}")
            return self._by_name[idx]
        raise TypeError(f"ImportModule indices must be str or int, not {type(idx).__name__}")

    def __contains__(self, idx: str | int) -> bool:
        if isinstance(idx, int):
            return idx in self._by_ordinal
        if isinstance(idx, str):
            return idx in self._by_name
        return False

    @cached_property
    def header(self) -> c_pe.IMAGE_EXPORT_DIRECTORY:
        """The export directory header."""
        self.pe.vfh.seek(self.address)
        return c_pe.IMAGE_EXPORT_DIRECTORY(self.pe.vfh)

    @property
    def timestamp(self) -> datetime.datetime | None:
        """The timestamp of the export directory, or ``None`` if the PE file is compiled as reproducible."""
        if self.pe.is_reproducible():
            return None
        return from_unix(self.header.TimeDateStamp)

    @cached_property
    def name(self) -> str | None:
        """The name of the export directory, if available."""
        if self.header.Name:
            self.pe.vfh.seek(self.header.Name)
            return c_pe.char[None](self.pe.vfh).decode()
        return None

    @property
    def base(self) -> int:
        """The base ordinal of the exported functions."""
        return self.header.Base

    @cached_property
    def functions(self) -> list[ExportFunction]:
        """List of exported functions."""
        result = []

        self.pe.vfh.seek(self.header.AddressOfFunctions)
        addresses = c_pe.ULONG[self.header.NumberOfFunctions](self.pe.vfh)

        self.pe.vfh.seek(self.header.AddressOfNames)
        names = c_pe.ULONG[self.header.NumberOfNames](self.pe.vfh)

        self.pe.vfh.seek(self.header.AddressOfNameOrdinals)
        ordinals = c_pe.USHORT[self.header.NumberOfNames](self.pe.vfh)

        for name_ptr, ordinal in zip(names, ordinals):
            self.pe.vfh.seek(name_ptr)
            name = c_pe.CHAR[None](self.pe.vfh).decode()

            address = addresses[ordinal]
            forwarder = None
            if self.address <= address < self.address + self.size:
                self.pe.vfh.seek(address)
                forwarder = c_pe.CHAR[None](self.pe.vfh).decode()

            result.append(ExportFunction(self, ordinal, name, address, forwarder))

        return result

    @cached_property
    def _by_name(self) -> dict[str, ExportFunction]:
        """A mapping of exported function names to their :class:`ExportFunction`."""
        return {func.name: func for func in self.functions}

    @cached_property
    def _by_ordinal(self) -> dict[int, ExportFunction]:
        """A mapping of exported function ordinals to their :class:`ExportFunction`."""
        return {func.ordinal: func for func in self.functions}


@dataclass
class ExportFunction:
    directory: ExportDirectory
    """The export directory this function belongs to."""
    unbiased_ordinal: int
    """The unbiased ordinal of the exported function."""
    name: str
    """The name of the exported function."""
    address: int
    """The address of the exported function."""
    forwarder: str | None = None
    """The forwarder of the exported function, if it is a forwarder."""

    def __repr__(self) -> str:
        if self.forwarder:
            return f"<ExportFunction ordinal={self.ordinal} name={self.name!r} forwarder={self.forwarder!r}>"
        return f"<ExportFunction ordinal={self.ordinal} name={self.name!r} address={self.address:#x}>"

    @property
    def ordinal(self) -> int:
        """The unbiased ordinal with the base ordinal added."""
        return self.unbiased_ordinal + self.directory.base
