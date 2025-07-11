from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory

if TYPE_CHECKING:
    from collections.abc import Iterator


class SecurityDirectory(DataDirectory):
    """The security directory of a PE file."""

    def __repr__(self) -> str:
        return f"<SecurityDirectory entries={len(self.entries)}>"

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[Certificate]:
        return iter(self.entries)

    def __getitem__(self, idx: int) -> Certificate:
        return self.entries[idx]

    @cached_property
    def entries(self) -> list[Certificate]:
        """List of certificates in the security directory."""
        result = []

        offset = self.address
        while offset < self.address + self.size:
            # Note: the offset here is a file offset, not an RVA
            self.pe.fh.seek(offset)

            certificate = c_pe.WIN_CERTIFICATE(self.pe.fh)
            if certificate.dwLength == 0:
                break

            result.append(Certificate(certificate))
            offset += certificate.dwLength
            offset += -offset & 7  # Align to 8 bytes

        return result


class Certificate:
    """A single certificate entry in the security directory."""

    def __init__(self, certificate: c_pe.WIN_CERTIFICATE):
        self.certificate = certificate

    def __repr__(self) -> str:
        return f"<Certificate revision={self.revision} type={self.type.name} size={self.certificate.dwLength}>"

    @property
    def revision(self) -> int:
        """The revision of the certificate."""
        return self.certificate.wRevision

    @property
    def type(self) -> c_pe.WIN_CERT_TYPE:
        """The type of the certificate."""
        return self.certificate.wCertificateType

    @property
    def size(self) -> int:
        """The size of the certificate."""
        return self.certificate.dwLength

    @property
    def data(self) -> bytes:
        """The raw data of the certificate."""
        return self.certificate.bCertificate
