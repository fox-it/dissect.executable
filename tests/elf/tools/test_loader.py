from __future__ import annotations

import os
import platform
import subprocess
import sys

import pytest

from tests._utils import absolute_path


@pytest.mark.skipif(os.name != "posix" and sys.platform != "darwin", reason="Loader only supports POSIX systems")
@pytest.mark.skipif(
    platform.machine() not in ("x86_64", "aarch64"), reason="Loader only supports x86_64 and aarch64 architectures"
)
def test_loader() -> None:
    """Test that the loader can load a simple ELF binary."""
    path = absolute_path(f"_data/elf/hello_world-{platform.machine()}-static.bin")

    # Run the loader in a subprocess to avoid affecting the test runner process
    # The loader currently does not clean up after itself and will segfault
    result = subprocess.run([sys.executable, "-m", "dissect.executable.elf.tools.loader", path], capture_output=True)
    assert result.stdout == b"Kusjes van SRT <3\n"
