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


class DelayImportDirectory(DataDirectory):
    """The delay import directory of a PE file."""

    def __repr__(self) -> str:
        return f"<DelayImportDirectory modules={len(self.modules)}>"

    def __len__(self) -> int:
        return len(self.modules)

    def __getitem__(self, idx: str | int) -> DelayImportModule:
        if isinstance(idx, int):
            return self.modules[idx]
        if isinstance(idx, str):
            if idx not in self._by_name:
                raise KeyError(f"Delay import module {idx!r} not found")
            return self._by_name[idx]
        raise TypeError(f"DelayImportDirectory indices must be str or int, not {type(idx).__name__}")

    def __contains__(self, name: str) -> bool:
        if isinstance(name, str):
            return name in self._by_name
        return False

    @cached_property
    def modules(self) -> list[DelayImportModule]:
        """List of delay imported modules."""
        self.pe.vfh.seek(self.address)
        return [
            DelayImportModule(self.pe, descriptor) for descriptor in c_pe.IMAGE_DELAYLOAD_DESCRIPTOR[None](self.pe.vfh)
        ]

    @cached_property
    def _by_name(self) -> dict[str, DelayImportModule]:
        """A mapping of module names to their :class:`DelayImportModule`."""
        return {module.name: module for module in self.modules}


class DelayImportModule:
    """A module delay imported by a PE file, containing its functions."""

    def __init__(self, pe: PE, descriptor: c_pe.IMAGE_DELAYLOAD_DESCRIPTOR):
        self.pe = pe
        self.descriptor = descriptor

    def __repr__(self) -> str:
        return f"<DelayImportModule name={self.name!r} functions={len(self.functions)}>"

    def __iter__(self) -> Iterator[DelayImportFunction]:
        return iter(self.functions)

    def __getitem__(self, idx: str | int) -> DelayImportFunction:
        if isinstance(idx, int):
            return self._by_ordinal[idx]
        if isinstance(idx, str):
            if idx not in self._by_name:
                raise KeyError(f"Delay import function {idx!r} not found in module {self.name!r}")
            return self._by_name[idx]
        raise TypeError(f"DelayImportModule indices must be str or int, not {type(idx).__name__}")

    def __contains__(self, idx: str | int) -> bool:
        if isinstance(idx, int):
            return idx in self._by_ordinal
        if isinstance(idx, str):
            return idx in self._by_name
        return False

    @property
    def timestamp(self) -> datetime.datetime | None:
        """The timestamp of the target DLL of this delay import module, or ``None`` if the PE file is
        compiled as reproducible.

        Will be ``0`` (so epoch) if it's not bound yet.
        """
        if self.pe.is_reproducible():
            return None
        return from_unix(self.descriptor.TimeDateStamp)

    @cached_property
    def name(self) -> str:
        """The name of the delay import module."""
        self.pe.vfh.seek(self.descriptor.DllNameRVA)
        return c_pe.CHAR[None](self.pe.vfh).decode()

    @cached_property
    def functions(self) -> list[DelayImportFunction]:
        """List of delay imported functions from this module."""
        ctype = c_pe.IMAGE_THUNK_DATA64 if self.pe.is_64bit() else c_pe.IMAGE_THUNK_DATA32

        self.pe.vfh.seek(self.descriptor.ImportNameTableRVA)
        name_table = ctype[None](self.pe.vfh)

        self.pe.vfh.seek(self.descriptor.ImportAddressTableRVA)
        address_table = ctype[None](self.pe.vfh)

        bound_table = []
        if self.descriptor.BoundImportAddressTableRVA:
            self.pe.vfh.seek(self.descriptor.BoundImportAddressTableRVA)
            bound_table = ctype[None](self.pe.vfh)
        # If we are not bound (e.g. PE file on disk instead of in memory), create an empty table
        bound_table = bound_table or [None] * len(name_table)

        unload_table = []
        if self.descriptor.UnloadInformationTableRVA:
            self.pe.vfh.seek(self.descriptor.UnloadInformationTableRVA)
            unload_table = ctype[None](self.pe.vfh)
        # If we are not unloading (e.g. PE file on disk instead of in memory), create an empty table
        unload_table = unload_table or [None] * len(name_table)

        return [
            DelayImportFunction(self, name_thunk, address_thunk, bound_thunk, unload_thunk)
            for name_thunk, address_thunk, bound_thunk, unload_thunk in zip(
                name_table, address_table, bound_table, unload_table
            )
        ]

    @cached_property
    def _by_name(self) -> dict[str, DelayImportFunction]:
        """A mapping of imported function names to their :class:`DelayImportFunction`."""
        return {func.name: func for func in self.functions if func.name is not None}

    @cached_property
    def _by_ordinal(self) -> dict[int, DelayImportFunction]:
        """A mapping of function ordinals to their :class:`DelayImportFunction`."""
        return {func.ordinal: func for func in self.functions}


class DelayImportFunction:
    """A function delay imported from a module."""

    def __init__(
        self,
        module: DelayImportModule,
        name_thunk: c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64,
        address_thunk: c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64,
        bound_thunk: c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64 | None = None,
        unload_thunk: c_pe.IMAGE_THUNK_DATA32 | c_pe.IMAGE_THUNK_DATA64 | None = None,
    ):
        self.module = module
        self.name_thunk = name_thunk
        self.address_thunk = address_thunk

        if name_thunk.u1.Ordinal & (c_pe.IMAGE_ORDINAL_FLAG64 if module.pe.is_64bit() else c_pe.IMAGE_ORDINAL_FLAG32):
            self.ordinal = name_thunk.u1.Ordinal & 0xFFFF
            self.name = None
        else:
            self.module.pe.vfh.seek(name_thunk.u1.AddressOfData & (c_pe.IMAGE_ORDINAL_FLAG32 - 1))
            import_by_name = c_pe.IMAGE_IMPORT_BY_NAME(self.module.pe.vfh)
            self.ordinal = import_by_name.Hint
            self.name = import_by_name.Name.decode()

        self.address = address_thunk.u1.Function
        self.bound_address = bound_thunk.u1.Function if bound_thunk else None
        self.unload_address = unload_thunk.u1.Function if unload_thunk else None

    def __repr__(self) -> str:
        address = hex(self.address) if self.address is not None else "None"
        bound_address = hex(self.bound_address) if self.bound_address is not None else "None"
        unload_address = hex(self.unload_address) if self.unload_address is not None else "None"
        return f"<DelayImportFunction name={self.name!r} ordinal={self.ordinal} address={address} bound_address={bound_address} unload_address={unload_address}>"  # noqa: E501
