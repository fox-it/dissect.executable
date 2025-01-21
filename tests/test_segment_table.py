from __future__ import annotations

from io import BytesIO
from unittest.mock import Mock, patch

import pytest

from dissect.executable.elf.elf import SegmentTable, c_elf_64


@pytest.fixture
def segment_table(entries: int) -> SegmentTable:
    elf = Mock()
    elf.header.e_phnum = entries
    elf.header.e_phoff = 0x0
    elf.header.e_phentsize = 0x10
    elf.fh = BytesIO(b"\x00" * 20)
    return SegmentTable.from_elf(elf)


@pytest.mark.parametrize("entries", [0])
def test_segment_table_unknown_index(segment_table: SegmentTable) -> None:
    with pytest.raises(IndexError):
        assert segment_table[20]


@pytest.mark.parametrize("entries", [1])
def test_segment_table_known(segment_table: SegmentTable) -> None:
    with patch("dissect.executable.elf.elf.Segment") as mocked_segment:
        assert segment_table[0] == mocked_segment.from_segment_table.return_value


def create_segment_table(amount: int, random_data: bytes) -> SegmentTable:
    data_size = len(random_data)
    segments_data = []
    for idx in range(amount):
        data = c_elf_64.Phdr(p_offset=len(c_elf_64.Phdr) * amount + idx * data_size, p_filesz=data_size).dumps()
        segments_data.append(data)

    segments_data.append(random_data * amount)
    segment_data = BytesIO(b"".join(segments_data))
    return SegmentTable(segment_data, 0, amount, len(c_elf_64.Phdr))


def test_dump_data() -> None:
    segment_table = create_segment_table(2, b"hello_world")
    segment_table[0].patch(b"new_data")
    data = b""
    for segment_tuple in segment_table.dump_data():
        data += segment_tuple[1]
    assert len(data) == len(b"hello_world" + b"new_data")


def test_dump_table() -> None:
    segment_table = create_segment_table(2, b"hello_world")
    segment_table[0].patch(b"new_data")
    assert len(segment_table.dump_table()[1]) == 2 * len(c_elf_64.Phdr)
