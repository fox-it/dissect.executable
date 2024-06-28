from dissect.executable import PE
from dissect.executable.pe import Builder, Patcher
from dissect.executable.pe.helpers.c_pe import pestruct


def test_build_new_pe_lfanew():
    builder = Builder()
    builder.new()
    pe = builder.pe

    assert pe.mz_header.e_lfanew == 0x8C


def test_build_new_x86_pe_exe():
    builder = Builder(arch="x86")
    builder.new()
    pe = builder.pe

    pe.pe_file.seek(len(pe.mz_header))
    stub = pe.pe_file.read(pe.mz_header.e_lfanew - len(pe.mz_header))
    assert stub[14 : 73 - 4] == b"This program is made with dissect.pe <3 kusjesvanSRT <3"

    assert pe.file_header.Characteristics & pestruct.ImageCharacteristics.IMAGE_FILE_32BIT_MACHINE == 0x0100


def test_build_new_x64_pe_exe():
    builder = Builder(arch="x64")
    builder.new()
    pe = builder.pe

    pe.pe_file.seek(len(pe.mz_header))
    stub = pe.pe_file.read(pe.mz_header.e_lfanew - len(pe.mz_header))
    assert stub[14 : 73 - 4] == b"This program is made with dissect.pe <3 kusjesvanSRT <3"

    assert pe.file_header.Characteristics & pestruct.ImageCharacteristics.IMAGE_FILE_32BIT_MACHINE != 0x0100


def test_build_new_x86_pe_dll():
    builder = Builder(arch="x86", dll=True)
    builder.new()
    pe = builder.pe

    assert pe.file_header.Characteristics & pestruct.ImageCharacteristics.IMAGE_FILE_32BIT_MACHINE == 0x0100
    assert pe.file_header.Characteristics & pestruct.ImageCharacteristics.IMAGE_FILE_DLL == 0x2000


def test_build_new_x64_pe_dll():
    builder = Builder(arch="x64", dll=True)
    builder.new()
    pe = builder.pe

    assert pe.file_header.Characteristics & pestruct.ImageCharacteristics.IMAGE_FILE_32BIT_MACHINE != 0x0100
    assert pe.file_header.Characteristics & pestruct.ImageCharacteristics.IMAGE_FILE_DLL == 0x2000


def test_build_new_pe_with_custom_section():
    builder = Builder()
    builder.new()
    pe = builder.pe

    pe.add_section(name=".SRT", data=b"kusjesvanSRT")

    patcher = Patcher(pe=pe)

    new_pe = PE(pe_file=patcher.build)

    assert new_pe.sections[".SRT"].name == ".SRT"
    assert new_pe.sections[".SRT"].size == 12
    assert new_pe.sections[".SRT"].data == b"kusjesvanSRT"
