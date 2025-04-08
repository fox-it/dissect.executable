# Local imports
from dissect.executable import PE
from dissect.executable.pe import Patcher

from .util import data_file


def test_add_imports() -> None:
    dllname = "kusjesvanSRT.dll"
    functions = ["PressButtons", "LooseLips"]

    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)
        pe.imports.add(dllname=dllname, functions=functions)

        patcher = Patcher(pe=pe)
        new_pe = PE(pe_file=patcher.build())

        assert "kusjesvanSRT.dll" in new_pe.imports

        custom_dll_imports = [i.name for i in new_pe.imports["kusjesvanSRT.dll"].functions]
        assert "PressButtons" in custom_dll_imports
        assert "LooseLips" in custom_dll_imports


def test_resize_section_smaller() -> None:
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

        pe.sections.get(name=".text").data = b"kusjesvanSRT, patched with dissect"

        patcher = Patcher(pe=pe)
        new_pe = PE(pe_file=patcher.build())

        assert new_pe.sections.get(name=".text").size == len(b"kusjesvanSRT, patched with dissect")
        assert (
            new_pe.sections.get(name=".text").data[: len(b"kusjesvanSRT, patched with dissect")]
            == b"kusjesvanSRT, patched with dissect"
        )


def test_resize_section_bigger() -> None:
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

        original_size = pe.sections.get(name=".rdata").size

        pe.sections.get(name=".rdata", patch=True).data += b"kusjesvanSRT, patched with dissect" * 100

        patcher = Patcher(pe=pe)
        new_pe = PE(pe_file=patcher.build())

        assert new_pe.sections.get(name=".rdata").size == original_size + len(
            b"kusjesvanSRT, patched with dissect" * 100
        )


def test_resize_resource_smaller() -> None:
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

        for e in pe.resources.by_type(rsrc_id="Manifest"):
            e.data = b"kusjesvanSRT, patched with dissect"

        patcher = Patcher(pe=pe)
        new_pe = PE(pe_file=patcher.build())

        assert [patched.data for patched in new_pe.resources.by_type(rsrc_id="Manifest")] == [
            b"kusjesvanSRT, patched with dissect"
        ]


def test_resize_resource_bigger() -> None:
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)

        for e in pe.resources.by_type(rsrc_id="Manifest"):
            e.data = b"kusjesvanSRT, patched with dissect" + e.data

        patcher = Patcher(pe=pe)
        new_pe = PE(pe_file=patcher.build())

        assert [
            patched.data[: len(b"kusjesvanSRT, patched with dissect")]
            for patched in new_pe.resources.by_type(rsrc_id="Manifest")
        ] == [b"kusjesvanSRT, patched with dissect"]


def test_add_section() -> None:
    with data_file("testexe.exe").open("rb") as pe_fh:
        pe = PE(pe_file=pe_fh)
        pe.add_section(name=".SRT", data=b"kusjesvanSRT")

        patcher = Patcher(pe=pe)
        new_pe = PE(pe_file=patcher.build())

        assert ".SRT" in new_pe.sections.sections()
        assert new_pe.sections.get(name=".SRT").data == b"kusjesvanSRT"
