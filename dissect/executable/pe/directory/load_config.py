from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from dissect.util.ts import from_unix

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    import datetime


class LoadConfigDirectory(DataDirectory):
    """The load configuration directory of a PE file."""

    @cached_property
    def config(self) -> c_pe.IMAGE_LOAD_CONFIG_DIRECTORY32 | c_pe.IMAGE_LOAD_CONFIG_DIRECTORY64:
        """The load configuration directory header."""
        self.pe.vfh.seek(self.address)
        ctype = c_pe.IMAGE_LOAD_CONFIG_DIRECTORY64 if self.pe.is_64bit() else c_pe.IMAGE_LOAD_CONFIG_DIRECTORY32
        return ctype(self.pe.vfh)

    @property
    def timestamp(self) -> datetime.datetime | None:
        """The timestamp of the load configuration directory, or ``None`` if the PE file is compiled as reproducible."""
        if self.pe.is_reproducible():
            return None
        return from_unix(self.config.TimeDateStamp)

    @property
    def security_cookie(self) -> int:
        """The security cookie address."""
        return self.config.SecurityCookie

    @property
    def guard_flags(self) -> c_pe.IMAGE_GUARD:
        """The guard flags."""
        return self.config.GuardFlags & ~c_pe.IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK

    @property
    def chpe(
        self,
    ) -> c_pe.IMAGE_ARM64EC_METADATA | c_pe.IMAGE_ARM64EC_METADATA_V2 | c_pe.IMAGE_CHPE_METADATA_X86 | None:
        """The CHPE (Compiled Hybrid Portable Executable) metadata."""
        if not self.config.CHPEMetadataPointer:
            return None

        rva = self.pe.va_to_rva(self.config.CHPEMetadataPointer)
        self.pe.vfh.seek(rva)
        if self.pe.machine == c_pe.IMAGE_FILE_MACHINE.ARM64:
            version = c_pe.ULONG(self.pe.vfh)
            self.pe.vfh.seek(rva)
            if version == 2:
                return c_pe.IMAGE_ARM64EC_METADATA_V2(self.pe.vfh)
            return c_pe.IMAGE_ARM64EC_METADATA(self.pe.vfh)
        return c_pe.IMAGE_CHPE_METADATA_X86(self.pe.vfh)
