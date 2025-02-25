from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.executable.pe.c_pe import c_pe

if TYPE_CHECKING:
    from dissect.executable.pe.helpers.sections import PESection
    from dissect.executable.pe.pe import PE


class TLSManager:
    """Base class to manage the TLS entries of a PE file.

    Args:
        pe: The PE object to manage the TLS entries for.
    """

    def __init__(self, pe: PE, section: PESection):
        self.pe = pe
        self.section = section
        self.callbacks = []
        self.tls: c_pe._IMAGE_TLS_DIRECTORY32 | c_pe._IMAGE_TLS_DIRECTORY64 = None

        self._read_address: type[c_pe.uint64 | c_pe.uint32] = None
        self._tls_directory: type[c_pe._IMAGE_TLS_DIRECTORY32 | c_pe._IMAGE_TLS_DIRECTORY64] = None
        self._data = b""
        self._image_base = pe.optional_header.ImageBase

        self.set_architecture(pe)
        self.parse_tls()

    def set_architecture(self, pe: PE) -> None:
        if pe.is64bit():
            self._read_address = c_pe.uint64
            self._tls_directory = c_pe._IMAGE_TLS_DIRECTORY64
        else:
            self._read_address = c_pe.uint32
            self._tls_directory = c_pe._IMAGE_TLS_DIRECTORY32

    def parse_tls(self) -> None:
        """Parse the TLS directory entry of the PE file when present."""

        tls_data = BytesIO(self.section.data)
        self.tls = self._tls_directory(tls_data)

        self.pe.seek(self.tls.AddressOfCallBacks - self._image_base)

        # Parse the TLS callback addresses if present
        while True:
            callback_address = self._read_address(self.pe)
            if not callback_address:
                break
            self.callbacks.append(callback_address)

        # Read the TLS data
        self._data = self.read_data()

    @property
    def size(self) -> int:
        """Return the size of the TLS data.

        Returns:
            The size of the TLS data in bytes.
        """

        return self.tls.EndAddressOfRawData - self.tls.StartAddressOfRawData

    @size.setter
    def size(self, value: int) -> None:
        """Setter to set the size of the TLS data to the specified value.

        Args:
            value: The new size of the TLS data in bytes.
        """

        self.tls.EndAddressOfRawData = self.tls.StartAddressOfRawData + value

    def read_data(self) -> bytes:
        """Read the TLS data from the PE file.

        Returns:
            The TLS data in bytes.
        """

        return self.pe.virtual_read(
            address=self.tls.StartAddressOfRawData - self._image_base,
            size=self.size,
        )

    @property
    def data(self) -> bytes:
        """Return the TLS data.

        Returns:
            The TLS data in bytes.
        """

        return self._data

    @data.setter
    def data(self, value: bytes) -> None:
        """Dynamically update the TLS directory data if the user changes the data.

        Args:
            value: The new TLS data to write to the PE file.
        """

        self._data = value
        section_data = BytesIO(self.section.data)

        if len(self._data) != self.size:
            # Update the size of the TLS data
            self.size = len(self._data)

        # Write the new TLS values to the section
        section_data.write(self.tls.dumps())

        # Write the new TLS data to the section
        start_address_rva = self.tls.StartAddressOfRawData - self._image_base
        start_address_section_offset = start_address_rva - self.section.virtual_address
        section_data.seek(start_address_section_offset)
        section_data.write(self._data)

        # Update the section itself
        section_data.seek(0)
        self.section.data = section_data.read()

    def add(self) -> None:
        raise NotImplementedError
