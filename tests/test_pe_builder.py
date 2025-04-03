from dissect.executable import PE
from dissect.executable.pe import Builder, Patcher
from dissect.executable.pe.c_pe import c_pe


def test_build_new_pe_lfanew() -> None:
    builder = Builder()
    builder.new()
    pe = builder.pe

    assert pe.mz_header.e_lfanew == 0x8C


def test_build_new_x86_pe_exe() -> None:
    builder = Builder(arch="x86")
    builder.new()
    pe = builder.pe

    pe.pe_file.seek(len(pe.mz_header))
    stub = pe.pe_file.read(pe.mz_header.e_lfanew - len(pe.mz_header))
    assert stub[14 : 73 - 4] == b"This program is made with dissect.pe <3 kusjesvanSRT <3"

    assert pe.file_header.Characteristics & c_pe.ImageCharacteristics.IMAGE_FILE_32BIT_MACHINE


def test_build_new_x64_pe_exe() -> None:
    builder = Builder(arch="x64")
    builder.new()
    pe = builder.pe

    pe.pe_file.seek(len(pe.mz_header))
    stub = pe.pe_file.read(pe.mz_header.e_lfanew - len(pe.mz_header))
    assert stub[14 : 73 - 4] == b"This program is made with dissect.pe <3 kusjesvanSRT <3"

    assert not (pe.file_header.Characteristics & c_pe.ImageCharacteristics.IMAGE_FILE_32BIT_MACHINE)


def test_build_new_x86_pe_dll() -> None:
    builder = Builder(arch="x86", dll=True)
    builder.new()
    pe = builder.pe

    assert pe.file_header.Characteristics & c_pe.ImageCharacteristics.IMAGE_FILE_32BIT_MACHINE
    assert pe.file_header.Characteristics & c_pe.ImageCharacteristics.IMAGE_FILE_DLL


def test_build_new_x64_pe_dll() -> None:
    builder = Builder(arch="x64", dll=True)
    builder.new()
    pe = builder.pe

    assert not (pe.file_header.Characteristics & c_pe.ImageCharacteristics.IMAGE_FILE_32BIT_MACHINE)
    assert pe.file_header.Characteristics & c_pe.ImageCharacteristics.IMAGE_FILE_DLL


def test_build_new_pe_with_custom_section() -> None:
    builder = Builder()
    builder.new()
    pe = builder.pe

    pe.add_section(name=".SRT", data=b"kusjesvanSRT")

    patcher = Patcher(pe=pe)

    new_pe = PE(pe_file=patcher.build())

    section_manager = new_pe.sections

    section = section_manager.get(name=".SRT")
    assert section.name == ".SRT"
    assert section.size == 12
    assert section.data == b"kusjesvanSRT"
