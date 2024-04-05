from __future__ import annotations

import math
from typing import BinaryIO, Iterable, Tuple

# External imports
from dissect.util.stream import AlignedStream


def pages(size: int, page_size: int) -> int:
    """Return the number of pages within a page stream.

    Args:
        size: The size of the root page.
        page_size: The size of the current page.

    Returns:
        The number of pages as an `int` type.
    """

    return math.ceil(size / page_size)


class PageStream(AlignedStream):
    """Class to parse the streams within a PDB file. A PDB file is basically a file that
    contains multiple other files in the form of streams.

    PDB layout (from: https://github.com/microsoft/microsoft-pdb)

    STREAM 1        = Pdb Header                  - Version information, and information to connect this PDB to the EXE
    STREAM 2        = Tpi (Type Manager)          - All the types used in the executable.
    STREAM 3        = Dbi (Debug Manager)         - Holds section contributions, and list of 'Mods'
    STREAM 4        = NameMap                     - Holds a hashed string table
    STREAM 4-(n+4)  = n Mod's(Module Information) - Each Mod stream holds symbols and line numbers for one compiland
    STREAM n+4      = Global Symbol Hash          - An index that allows searching in global symbols by name
    STREAM n+5      = Public Symbol Hash          - An index that allows searching in public symbols by addresses
    STREAM n+6      = Symbol Records              - Actual symbol records of global and public symbols
    STREAM n+7      = Type Hash                   - Hash used by the TPI stream.

    Args:
        fh: A file handle to a PDB file.
        pages: A list with the amount of pages found within the PDB file.
        size: Size of the root stream within the PDB file.
        page_size: Size of the page.
    """

    def __init__(self, fh: BinaryIO, pages: list[int], size: int, page_size: int) -> None:
        super().__init__(size=size)
        self.fh = fh
        self.pages = pages
        self.size = size
        self.page_size = page_size

    def _read(self, offset: int, length: int) -> bytes:
        """Read functionality implementation for page streams.

        Args:
            size: Amount of bytes to read.

        Returns:
            The amount of `bytes` that needed to be read by size.
        """

        page_num_start, offset_in_page = divmod(offset, self.page_size)

        page_num_end, end_offset = divmod(offset + length, self.page_size)
        page_data = self._read_pages(self.pages[page_num_start : page_num_end + 1])

        return page_data[offset_in_page:][:length]

    def _get_page(self, offset: int) -> Tuple[int, int]:
        """Function to retrieve the start/end of a page and the start/end of the offset.

        Args:
            offset: The offset to use to retrieve the start/end of the page stream.

        Returns:
            The start/end of a page and the start/end offset as a `Tuple`.
        """

        return divmod(offset, self.page_size)

    def _read_pages(self, pages: Iterable) -> bytes:
        """Read the pages within the current page stream.

        Args:
            pages: The pages to read from the current stream.

        Returns:
            `bytes` containing the page stream.
        """

        result = []

        for page_number in pages:
            self.fh.seek(page_number * self.page_size)
            result.append(self.fh.read(self.page_size))

        return b"".join(result)
