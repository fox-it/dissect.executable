from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    from collections.abc import Iterator


class BaseRelocationDirectory(DataDirectory):
    """The base relocation directory of a PE file."""

    def __repr__(self) -> str:
        return f"<BaseRelocationDirectory entries={len(self.entries)}>"

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[BaseRelocation]:
        return iter(self.entries)

    def __getitem__(self, idx: int) -> BaseRelocation:
        return self.entries[idx]

    @cached_property
    def entries(self) -> list[BaseRelocation]:
        """List of base relocation entries."""
        result = []

        offset = self.address
        while offset < self.address + self.size:
            self.pe.vfh.seek(offset)

            block = c_pe._IMAGE_BASE_RELOCATION(self.pe.vfh)
            if block.SizeOfBlock == 0:
                break

            page_rva = block.VirtualAddress

            num_entries = (block.SizeOfBlock - len(c_pe._IMAGE_BASE_RELOCATION)) // len(c_pe.USHORT)
            result.extend(
                BaseRelocation(c_pe.IMAGE_REL_BASED(entry >> 12), page_rva + (entry & 0xFFF))
                for entry in c_pe.USHORT[num_entries](self.pe.vfh)
                if (entry >> 12) != 0  # Skip IMAGE_REL_BASED_ABSOLUTE (0)
            )
            offset += block.SizeOfBlock
            offset += -offset & 3  # Align to 4 bytes

        return result


@dataclass
class BaseRelocation:
    """A single base relocation entry in the base relocation directory."""

    type: c_pe.IMAGE_REL_BASED
    rva: int

    def __repr__(self) -> str:
        return f"<BaseRelocation rva={self.rva:#x} type={self.type.name or self.type.value}>"
