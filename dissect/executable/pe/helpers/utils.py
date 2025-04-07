from __future__ import annotations

import struct
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.executable.pe import PE, PESection


@lru_cache
def create_struct(packing: str) -> struct.Struct:
    return struct.Struct(packing)


def align_data(data: bytes, blocksize: int) -> bytes:
    """Align the new data according to the file alignment as specified in the PE header.

    Args:
        data: The raw data that needs to be aligned.
        blocksize: The alignment to adhere to.

    Returns:
        Padded data if the data was not aligned to the blocksize.
    """

    needs_alignment = len(data) % blocksize
    return data if not needs_alignment else data + ((blocksize - needs_alignment) * b"\x00")


def align_int(integer: int, blocksize: int) -> int:
    """Align integer values to the specified section alignment described in the PE header.

    Args:
        integer: The address or value that needs to have an aligned value.
        blocksize: The alignment to adhere to.

    Returns:
        An aligned integer if the integer itself was not aligned yet.
    """

    needs_alignment = integer % blocksize
    return integer if not needs_alignment else integer + (blocksize - needs_alignment)


def pad(size: int) -> bytes:
    """Pad the data with null bytes.

    Args:
        size: The amount of null bytes to return.

    Returns:
        The null bytes as `bytes`.
    """
    return size * b"\x00"


class Manager:
    def __init__(self, pe: PE, section: PESection) -> None:
        self.pe = pe
        self.section = section

    def parse(self) -> None:
        raise NotImplementedError

    def add(self, *args, **kwargs) -> None:
        raise NotImplementedError

    def delete(self, *args, **kwargs) -> None:
        raise NotImplementedError

    def patch(self, *args, **kwargs) -> None:
        raise NotImplementedError
