import io
from contextlib import contextmanager
from typing import BinaryIO, Generator, Iterator


@contextmanager
def retain_file_offset(
    fobj: BinaryIO, offset: int = None, whence: int = io.SEEK_SET
) -> Generator[BinaryIO, None, None]:
    """Function to retain the file offset after searching for a specific pattern in the binary object.

    Args:
        fobj: The file-like object we're searching through.
        offset: The offset we need to retain.
        whence: The type of action we perform the seek operation with.

    Yields:
        The file-like object.
    """

    try:
        pos = fobj.tell()
        if offset is not None:
            fobj.seek(offset, whence)
        yield fobj
    finally:
        fobj.seek(pos)


def iter_find_needle(fobj: BinaryIO, needle: bytes, start_offset: int = None, max_offset: int = 0) -> Iterator[int]:
    """Return an iterator yielding `offset` for found `needle` bytes in file `fobj`.
    Side effects: file handle position due to seeking.
    Args:
        fobj: file like object
        needle: needle to search for
        start_offset: offset in file object to start searching from, if None it will search from current position
        max_offset: how far we search for into the file, 0 for no limit

    Yields:
        offset where `needle` was found in file `fobj`
    """

    needle_len = len(needle)
    overlap_len = needle_len - 1
    saved = b"\x00" * overlap_len
    if start_offset is not None:
        fobj.seek(start_offset)
    while True:
        pos = fobj.tell()
        if max_offset and pos > max_offset:
            break
        block = fobj.read(pos, min(8192, max_offset - start_offset))
        if not block:
            continue
        d = saved + block
        p = -1
        while True:
            p = d.find(needle, p + 1)
            if p == -1 or max_offset and p > max_offset:
                break
            offset = pos + p - overlap_len
            yield offset
        saved = d[-overlap_len:]
