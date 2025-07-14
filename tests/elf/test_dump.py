from __future__ import annotations

import filecmp
from typing import TYPE_CHECKING

import pytest

from dissect.executable import ELF
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    "path",
    [
        "_data/elf/hello_world.out",
        "_data/elf/hello_world.stripped.out",
    ],
)
def test_dump(path: str, tmp_path: Path) -> None:
    output_path = tmp_path / "output"
    input_path = absolute_path(path)

    with input_path.open("rb") as input_file:
        elf_file = ELF(input_file)
        with output_path.open("wb") as output:
            output.write(elf_file.dump())

    assert filecmp.cmp(input_path, output_path)
