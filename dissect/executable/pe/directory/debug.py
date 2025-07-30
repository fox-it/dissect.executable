from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.util.stream import RangeStream
from dissect.util.ts import from_unix

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator

    from dissect.executable.pe.pe import PE


class DebugDirectory(DataDirectory):
    """The debug directory of a PE file."""

    def __repr__(self) -> str:
        return f"<DebugDirectory entries={len(self.entries)}>"

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[DebugEntry]:
        return iter(self.entries)

    def __getitem__(self, idx: int) -> DebugEntry:
        return self.entries[idx]

    @cached_property
    def entries(self) -> list[DebugEntry]:
        """List of debug entries in the debug directory."""
        result = []

        self.pe.vfh.seek(self.address)
        for entry in c_pe.IMAGE_DEBUG_DIRECTORY[self.size // len(c_pe.IMAGE_DEBUG_DIRECTORY)](self.pe.vfh):
            cls = _DEBUG_TYPE_MAP.get(entry.Type, DebugEntry)
            result.append(cls(self.pe, entry))

        return result


class DebugEntry:
    """A single debug entry in the debug directory."""

    def __init__(self, pe: PE, entry: c_pe.IMAGE_DEBUG_DIRECTORY):
        self.pe = pe
        self.entry = entry

    def __repr__(self) -> str:
        return f"<DebugEntry type={self.type.name} size={self.size}>"

    @property
    def timestamp(self) -> datetime.datetime | None:
        """The timestamp of this debug entry, or ``None`` if the PE file is compiled as reproducible."""
        if self.pe.is_reproducible():
            return None
        return from_unix(self.entry.TimeDateStamp)

    @property
    def type(self) -> c_pe.IMAGE_DEBUG_TYPE:
        """The type of the debug entry."""
        return self.entry.Type

    @property
    def size(self) -> int:
        """The size of the debug entry."""
        return self.entry.SizeOfData

    @property
    def data(self) -> bytes:
        """The data of the debug entry."""
        with self.open() as fh:
            return fh.read()

    def open(self) -> BinaryIO:
        """Return a file-like object to read the debug entry data."""
        if not self.entry.AddressOfRawData:
            if self.pe.virtual:
                raise ValueError("Cannot access raw data of debug entry because it's not mapped into memory")

            fh = self.pe.fh
            address = self.entry.PointerToRawData
        else:
            fh = self.pe.vfh
            address = self.entry.AddressOfRawData

        return RangeStream(fh, address, self.size)


class CodeViewDebugEntry(DebugEntry):
    """A CodeView debug entry."""

    def __repr__(self) -> str:
        return f"<CodeViewDebugEntry signature={self.signature} pdb={self.pdb!r}>"

    @cached_property
    def info(self) -> c_pe.CV_INFO_PDB20 | c_pe.CV_INFO_PDB70 | c_pe.CV_INFO_MTOC:
        """The CodeView debug information."""
        with self.open() as fh:
            cv_signature = c_pe.ULONG(fh)
            fh.seek(0)

            if cv_signature == c_pe.CVINFO_PDB20_CVSIGNATURE:
                return c_pe.CV_INFO_PDB20(fh)

            if cv_signature == c_pe.CVINFO_PDB70_CVSIGNATURE:
                return c_pe.CV_INFO_PDB70(fh)

            if cv_signature == c_pe.CVINFO_MTOC_CVSIGNATURE:
                return c_pe.CV_INFO_MTOC(fh)

            raise ValueError("Not a CodeView debug entry")

    @property
    def signature(self) -> UUID | int | None:
        """The signature of the CodeView debug entry."""
        if isinstance(self.info, c_pe.CV_INFO_PDB20):
            return self.info.Signature

        if isinstance(self.info, (c_pe.CV_INFO_PDB70, c_pe.CV_INFO_MTOC)):
            return UUID(bytes_le=self.info.Signature)

        return None

    @property
    def age(self) -> int | None:
        """The age of the CodeView debug entry."""
        return getattr(self.info, "Age", None)

    @property
    def pdb(self) -> str:
        """The PDB filename of the CodeView debug entry."""
        return self.info.PdbFileName.decode()


class VcFeatureDebugEntry(DebugEntry):
    """A VC feature debug entry."""

    def __repr__(self) -> str:
        return f"<VcFeatureDebugEntry pre_vc11={self.pre_vc11} ccpp={self.ccpp} gs={self.gs} sdl={self.sdl} guards={self.guards}>"  # noqa: E501

    @cached_property
    def info(self) -> c_pe.VC_FEATURE:
        """The VC feature debug information."""
        with self.open() as fh:
            return c_pe.VC_FEATURE(fh)

    @property
    def pre_vc11(self) -> int:
        """Return the count for ``Pre-VC++ 11.00``."""
        return self.info.PreVC11

    @property
    def ccpp(self) -> int:
        """Return the count for ``C/C++``."""
        return self.info.CCpp

    @property
    def gs(self) -> int:
        """Return the count for ``/GS`` (number of guard stack)."""
        return self.info.Gs

    @property
    def sdl(self) -> int:
        """Return the count for ``/sdl`` (Security Development Lifecycle)."""
        return self.info.Sdl

    @property
    def guards(self) -> int:
        """Return the count for ``/guardN``."""
        return self.info.GuardN


class PogoDebugEntry(DebugEntry):
    """A POGO debug entry."""

    def __repr__(self) -> str:
        return f"<PogoDebugEntry entries={len(self.entries)}>"

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[tuple[int, int, str]]:
        return iter(self.entries)

    def __getitem__(self, idx: int) -> tuple[int, int, str]:
        return self.entries[idx]

    @cached_property
    def entries(self) -> list[tuple[int, int, str]]:
        """The POGO debug entries."""
        result = []

        with self.open() as fh:
            signature = c_pe.ULONG(fh)
            if signature not in (
                c_pe.IMAGE_DEBUG_POGO_SIGNATURE_ZERO,
                c_pe.IMAGE_DEBUG_POGO_SIGNATURE_LTCG,
                c_pe.IMAGE_DEBUG_POGO_SIGNATURE_PGU,
            ):
                raise NotImplementedError(f"Unsupported POGO signature: {signature:#x}")

            offset = fh.tell()
            while offset < self.size:
                fh.seek(offset)

                rva = c_pe.ULONG(fh)
                size = c_pe.ULONG(fh)
                label = c_pe.CHAR[None](fh).decode()

                result.append((rva, size, label))

                offset = fh.tell()
                offset += -offset & 3  # Align to 4 bytes

        return result


class ReproDebugEntry(DebugEntry):
    """A Repro debug entry."""

    def __repr__(self) -> str:
        return f"<ReproDebugEntry hash={self.hash.hex()!r}>"

    @property
    def hash(self) -> bytes:
        """The hash of the Repro debug entry."""
        with self.open() as fh:
            hash_size = c_pe.ULONG(fh)
            return fh.read(hash_size)


_DEBUG_TYPE_MAP: dict[c_pe.IMAGE_DEBUG_TYPE, type[DebugEntry]] = {
    c_pe.IMAGE_DEBUG_TYPE.CODEVIEW: CodeViewDebugEntry,
    c_pe.IMAGE_DEBUG_TYPE.VC_FEATURE: VcFeatureDebugEntry,
    c_pe.IMAGE_DEBUG_TYPE.POGO: PogoDebugEntry,
    c_pe.IMAGE_DEBUG_TYPE.REPRO: ReproDebugEntry,
}
