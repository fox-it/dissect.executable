from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from dissect.util.ts import from_unix

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    import datetime


class BoundImportDirectory(DataDirectory):
    """The bound import directory of a PE file."""

    def __repr__(self) -> str:
        return f"<BoundImportDirectory modules={len(self.modules)}>"

    def __len__(self) -> int:
        return len(self.modules)

    def __getitem__(self, idx: str | int) -> BoundImportModule:
        if isinstance(idx, int):
            return self.modules[idx]
        if isinstance(idx, str):
            if idx not in self._by_name:
                raise KeyError(f"Bound import module {idx!r} not found")
            return self._by_name[idx]
        raise TypeError(f"BoundImportDirectory indices must be str or int, not {type(idx).__name__}")

    def __contains__(self, name: str) -> bool:
        if isinstance(name, str):
            return name in self._by_name
        return False

    @cached_property
    def modules(self) -> list[BoundImportModule]:
        """List of bound imported modules."""
        result = []

        self.pe.vfh.seek(self.address)
        while self.pe.vfh.tell() < self.address + self.size:
            descriptor = c_pe.IMAGE_BOUND_IMPORT_DESCRIPTOR(self.pe.vfh)
            if not descriptor:
                break

            forwarders = []
            for _ in range(descriptor.NumberOfModuleForwarderRefs):
                forwarder = c_pe.IMAGE_BOUND_FORWARDER_REF(self.pe.vfh)
                if not forwarder:
                    break

                forwarders.append(BoundImportForwardReference(self, forwarder))

            result.append(BoundImportModule(self, descriptor, forwarders))

        return result

    @cached_property
    def _by_name(self) -> dict[str, BoundImportModule]:
        """A mapping of module names to their :class:`DelayImportModule`."""
        return {module.name: module for module in self.modules}


class BoundImportModule:
    """A module bound imported by a PE file, containing its functions."""

    def __init__(
        self,
        directory: BoundImportDirectory,
        descriptor: c_pe.IMAGE_BOUND_IMPORT_DESCRIPTOR,
        forwarders: list[BoundImportForwardReference],
    ):
        self.directory = directory
        self.descriptor = descriptor
        self.forwarders = forwarders

    @property
    def timestamp(self) -> datetime.datetime | None:
        """The timestamp of this bound import module, or ``None`` if the PE file is compiled as reproducible."""
        if self.directory.pe.is_reproducible():
            return None
        return from_unix(self.descriptor.TimeDateStamp)

    @property
    def name(self) -> str:
        self.directory.pe.vfh.seek(self.directory.address + self.descriptor.OffsetModuleName)
        return c_pe.CHAR[None](self.directory.pe.vfh).decode()


class BoundImportForwardReference:
    """A forward reference in a bound import module."""

    def __init__(
        self,
        directory: BoundImportDirectory,
        descriptor: c_pe.IMAGE_BOUND_FORWARDER_REF,
    ):
        self.directory = directory
        self.descriptor = descriptor

    @property
    def timestamp(self) -> datetime.datetime | None:
        """The timestamp of this bound import module, or ``None`` if the PE file is compiled as reproducible."""
        if self.directory.pe.is_reproducible():
            return None
        return from_unix(self.descriptor.TimeDateStamp)

    @property
    def name(self) -> str:
        self.directory.pe.vfh.seek(self.directory.address + self.descriptor.OffsetModuleName)
        return c_pe.CHAR[None](self.directory.pe.vfh).decode()
