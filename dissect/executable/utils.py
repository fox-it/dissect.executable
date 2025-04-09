from __future__ import annotations

import struct
from collections import OrderedDict
from functools import lru_cache
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from collections.abc import Iterable

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


T = TypeVar("T")


class Manager(Generic[T]):
    elements: list[T] | OrderedDict[str, T]

    def __init__(self, pe: PE, section: PESection) -> None:
        self.pe = pe
        self.section = section

    def __contains__(self, item: str | T) -> bool:
        return item in self.elements

    def __getitem__(self, item: str | int) -> T:
        return self.elements[item]

    def __iter__(self):
        yield from self.elements

    def __len__(self) -> int:
        return len(self.elements)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.elements}>"

    def values(self) -> Iterable[T]:
        raise NotImplementedError

    def parse(self) -> None:
        raise NotImplementedError

    def add(self, *args, **kwargs) -> None:
        raise NotImplementedError

    def delete(self, elem: int | str) -> None:
        raise NotImplementedError

    def patch(self, elem: int | str, data: bytes) -> None:
        raise NotImplementedError


class DictManager(Manager, Generic[T]):
    def __init__(self, pe: PE, section: PESection) -> None:
        super().__init__(pe, section)
        self.elements: OrderedDict[str, T] = OrderedDict()
        self.values = self.elements.values


class ListManager(Manager, Generic[T]):
    def __init__(self, pe: PE, section: PESection) -> None:
        super().__init__(pe, section)
        self.elements: list[T] = []
        self.values = lambda: self.elements
