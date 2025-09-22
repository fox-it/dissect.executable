# `import` is a reserved keyword in Python, so we can't name this file `import.py`
# Doorn in mijn oog

from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from dissect.util.ts import from_unix

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator

    from dissect.executable.pe.pe import PE


class ImportDirectory(DataDirectory):
    """The import directory of a PE file."""

    def __repr__(self) -> str:
        return f"<ImportDirectory modules={len(self.modules)}>"

    def __len__(self) -> int:
        return len(self.modules)

    def __getitem__(self, idx: str | int) -> ImportModule:
        if isinstance(idx, int):
            return self.modules[idx]
        if isinstance(idx, str):
            if idx not in self._by_name:
                raise KeyError(f"Import module {idx!r} not found")
            return self._by_name[idx]
        raise TypeError(f"ImportDirectory indices must be str or int, not {type(idx).__name__}")

    def __contains__(self, name: str) -> bool:
        if isinstance(name, str):
            return name in self._by_name
        return False

    @cached_property
    def modules(self) -> list[ImportModule]:
        """List of imported modules."""
        self.pe.vfh.seek(self.address)
        return [ImportModule(self.pe, descriptor) for descriptor in c_pe.IMAGE_IMPORT_DESCRIPTOR[None](self.pe.vfh)]

    @cached_property
    def _by_name(self) -> dict[str, ImportModule]:
        """A mapping of module names to their :class:`ImportModule`."""
        return {module.name: module for module in self.modules}


class ImportModule:
    """A module imported by a PE file, containing its functions."""

    def __init__(self, pe: PE, descriptor: c_pe.IMAGE_IMPORT_DESCRIPTOR):
        self.pe = pe
        self.descriptor = descriptor

    def __repr__(self) -> str:
        return f"<ImportModule name={self.name!r} functions={len(self.functions)}>"

    def __iter__(self) -> Iterator[ImportFunction]:
        return iter(self.functions)

    def __getitem__(self, idx: str | int) -> ImportFunction:
        if isinstance(idx, int):
            return self._by_ordinal[idx]
        if isinstance(idx, str):
            if idx not in self._by_name:
                raise KeyError(f"Import function {idx!r} not found in module {self.name!r}")
            return self._by_name[idx]
        raise TypeError(f"ImportModule indices must be str or int, not {type(idx).__name__}")

    def __contains__(self, idx: str | int) -> bool:
        if isinstance(idx, int):
            return idx in self._by_ordinal
        if isinstance(idx, str):
            return idx in self._by_name
        return False

    @property
    def timestamp(self) -> datetime.datetime | None:
        """The timestamp of this import module, or ``None`` if the PE file is compiled as reproducible."""
        if self.pe.is_reproducible():
            return None
        return from_unix(self.descriptor.TimeDateStamp)

    @cached_property
    def name(self) -> str:
        """The name of the imported module."""
        self.pe.vfh.seek(self.descriptor.Name)
        return c_pe.char[None](self.pe.vfh).decode()

    @cached_property
    def functions(self) -> list[ImportFunction]:
        """List of functions imported from this module."""
        ctype = c_pe.IMAGE_THUNK_DATA64 if self.pe.is_64bit() else c_pe.IMAGE_THUNK_DATA32

        self.pe.vfh.seek(self.descriptor.OriginalFirstThunk)
        lookup_table = ctype[None](self.pe.vfh)

        self.pe.vfh.seek(self.descriptor.FirstThunk)
        address_table = ctype[None](self.pe.vfh)

        return [
            ImportFunction(self, lookup_thunk, address_thunk)
            for lookup_thunk, address_thunk in zip(lookup_table, address_table, strict=False)
        ]

    @cached_property
    def _by_name(self) -> dict[str, ImportFunction]:
        """A mapping of imported function names to their :class:`ImportFunction`."""
        return {func.name: func for func in self.functions if func.name is not None}

    @cached_property
    def _by_ordinal(self) -> dict[int, ImportFunction]:
        """A mapping of imported function ordinals to their :class:`ImportFunction`."""
        return {func.ordinal: func for func in self.functions}


class ImportFunction:
    """A function imported from a module."""

    def __init__(
        self,
        module: ImportModule,
        lookup_thunk: c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64,
        address_thunk: c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64,
    ):
        self.module = module
        self.lookup_thunk = lookup_thunk
        self.address_thunk = address_thunk

        if lookup_thunk.u1.Ordinal & (c_pe.IMAGE_ORDINAL_FLAG64 if module.pe.is_64bit() else c_pe.IMAGE_ORDINAL_FLAG32):
            self.ordinal = lookup_thunk.u1.Ordinal & 0xFFFF
            self.name = None
        else:
            self.module.pe.vfh.seek(lookup_thunk.u1.AddressOfData & (c_pe.IMAGE_ORDINAL_FLAG32 - 1))
            import_by_name = c_pe.IMAGE_IMPORT_BY_NAME(self.module.pe.vfh)
            self.ordinal = import_by_name.Hint
            self.name = import_by_name.Name.decode()

        self.address = address_thunk.u1.Function if lookup_thunk.u1.Function != address_thunk.u1.Function else None

    def __repr__(self) -> str:
        address = hex(self.address) if self.address is not None else "None"
        return f"<ImportFunction name={self.name!r} ordinal={self.ordinal} address={address}>"
