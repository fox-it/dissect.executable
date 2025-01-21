from __future__ import annotations

import filecmp
from typing import TYPE_CHECKING

import pytest

from dissect.executable import ELF

from .util import data_file

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    "file_name",
    ["hello_world.out", "hello_world.stripped.out"],
)
def test_dump(tmp_path: Path, file_name: str) -> None:
    output_path = tmp_path / "output"
    input_path = data_file(file_name)

    with input_path.open("rb") as input_file:
        elf_file = ELF(input_file)
        with output_path.open("wb") as output:
            output.write(elf_file.dump())

    assert filecmp.cmp(input_path, output_path)
