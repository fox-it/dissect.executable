from __future__ import annotations

from io import BytesIO

from dissect.executable.elf.elf import Segment, c_elf_64


def create_segment(segment_data: bytes) -> Segment:
    c_segment = c_elf_64.Phdr(p_offset=len(c_elf_64.Phdr), p_filesz=len(segment_data)).dumps()
    fh = BytesIO(c_segment + segment_data)
    return Segment(fh, 0)


def test_segment() -> None:
    orig_data = b"hello_world"
    segment = create_segment(orig_data)
    assert segment.offset == len(c_elf_64.Phdr)
    assert segment.size == len(orig_data)
    assert segment.contents == orig_data
