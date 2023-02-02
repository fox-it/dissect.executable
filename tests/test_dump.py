import filecmp
from pathlib import Path

import pytest
from util import data_file

from dissect.executable import ELF


@pytest.mark.parametrize(
    "file_name",
    ["hello_world.out", "hello_world.stripped.out"],
)
def test_dump(tmp_path: Path, file_name: str):
    output_path = tmp_path / "output"
    input_path = data_file(file_name)

    with input_path.open("rb") as input_file:
        elf_file = ELF(input_file)
        with output_path.open("wb") as output:
            output.write(elf_file.dump())

    assert filecmp.cmp(input_path, output_path)
