from __future__ import annotations

from functools import cached_property
from typing import BinaryIO

from dissect.util.stream import RangeStream

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory


class ComDescriptorDirectory(DataDirectory):
    """The COM descriptor directory of a PE file.

    References:
        - https://www.codeproject.com/Articles/12585/The-NET-File-Format
    """

    @cached_property
    def descriptor(self) -> c_pe.IMAGE_COR20_HEADER:
        """The CLR 2.0 header descriptor."""
        self.pe.vfh.seek(self.address)
        return c_pe.IMAGE_COR20_HEADER(self.pe.vfh)

    @cached_property
    def metadata(self) -> ComMetadata:
        """The COM metadata directory."""
        return ComMetadata(self.pe, self.descriptor.MetaData.VirtualAddress, self.descriptor.MetaData.Size)


class ComMetadata(DataDirectory):
    """The COM metadata directory of the COM descriptor."""

    @cached_property
    def metadata(self) -> c_pe.IMAGE_COR20_METADATA:
        """The CLR 2.0 metadata descriptor."""
        self.pe.vfh.seek(self.address)
        return c_pe.IMAGE_COR20_METADATA(self.pe.vfh)

    @property
    def version(self) -> str:
        """The version as defined in the metadata."""
        return self.metadata.Version.decode().strip("\x00")

    @cached_property
    def streams(self) -> list[ComStream]:
        """A list of streams defined in the metadata."""
        result = []

        offset = self.address + len(self.metadata)
        for _ in range(self.metadata.NumberOfStreams):
            self.pe.vfh.seek(offset)
            header = c_pe.IMAGE_COR20_STREAM_HEADER(self.pe.vfh)

            result.append(ComStream(self, header.Offset, header.Size, header.Name.decode()))

            offset += len(header)
            offset += -offset & 3  # Align to 4 bytes

        return result


class ComStream:
    """A stream in the COM metadata."""

    def __init__(self, metadata: ComMetadata, offset: int, size: int, name: str):
        self.metadata = metadata
        self.offset = offset
        self.size = size
        self.name = name

    def __repr__(self) -> str:
        return f"<ComStream offset={self.offset:#x} size={self.size:#x} name={self.name!r}>"

    @property
    def data(self) -> bytes:
        """The data of the stream."""
        self.metadata.pe.vfh.seek(self.metadata.address + self.offset)
        return self.metadata.pe.vfh.read(self.size)

    def open(self) -> BinaryIO:
        """Open the stream for reading."""
        return RangeStream(self.metadata.pe.vfh, self.metadata.address + self.offset, self.size)
