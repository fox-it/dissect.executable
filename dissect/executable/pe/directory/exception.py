from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    from collections.abc import Iterator


class ExceptionDirectory(DataDirectory):
    """The exception directory of a PE file.

    Currently only shows the raw exception entries.
    """

    def __repr__(self) -> str:
        return f"<ExceptionDirectory entries={len(self.entries)}>"

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(
        self,
    ) -> Iterator[
        c_pe.IMAGE_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ARM_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_CE_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_MIPS_RUNTIME_FUNCTION_ENTRY
    ]:
        return iter(self.entries)

    def __getitem__(
        self, idx: int
    ) -> (
        c_pe.IMAGE_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ARM_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_CE_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_MIPS_RUNTIME_FUNCTION_ENTRY
    ):
        return self.entries[idx]

    @cached_property
    def entries(
        self,
    ) -> list[
        c_pe.IMAGE_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ARM_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_CE_RUNTIME_FUNCTION_ENTRY
        | c_pe.IMAGE_MIPS_RUNTIME_FUNCTION_ENTRY
    ]:
        """List of exception entries."""
        self.pe.vfh.seek(self.address)

        machine = self.pe.machine
        if machine in (c_pe.IMAGE_FILE_MACHINE.ARM, c_pe.IMAGE_FILE_MACHINE.THUMB, c_pe.IMAGE_FILE_MACHINE.ARMNT):
            ctype = c_pe.IMAGE_ARM_RUNTIME_FUNCTION_ENTRY
        elif machine == c_pe.IMAGE_FILE_MACHINE.ARM64:
            ctype = c_pe.IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY
        elif machine == c_pe.IMAGE_FILE_MACHINE.ALPHA:
            ctype = c_pe.IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY
        elif machine == c_pe.IMAGE_FILE_MACHINE.ALPHA64:
            ctype = c_pe.IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY
        elif machine in (
            c_pe.IMAGE_FILE_MACHINE.R3000,
            c_pe.IMAGE_FILE_MACHINE.R4000,
            c_pe.IMAGE_FILE_MACHINE.R10000,
            c_pe.IMAGE_FILE_MACHINE.WCEMIPSV2,
            c_pe.IMAGE_FILE_MACHINE.MIPS16,
            c_pe.IMAGE_FILE_MACHINE.MIPSFPU,
            c_pe.IMAGE_FILE_MACHINE.MIPSFPU16,
        ):
            ctype = c_pe.IMAGE_MIPS_RUNTIME_FUNCTION_ENTRY
        else:
            # May be wrong for esoteric architectures, but this is the default
            ctype = c_pe.IMAGE_RUNTIME_FUNCTION_ENTRY

        return ctype[self.size // len(ctype)](self.pe.vfh)
