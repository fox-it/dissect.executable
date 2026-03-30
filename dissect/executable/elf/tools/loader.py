from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.util
import enum
import json
import logging
import os
import platform
import random
import struct
import sys
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.executable.elf.c_elf import PF, PT
from dissect.executable.elf.elf import ELF

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.executable.elf.elf import Segment

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EXECUTABLE", "CRITICAL"))


class PROT(enum.IntFlag):
    READ = 0x1
    WRITE = 0x2
    EXEC = 0x4

    @classmethod
    def from_PF(cls, flags: PF) -> PROT:
        mapping = {
            PF.R: PROT.READ,
            PF.X: PROT.EXEC,
            PF.W: PROT.WRITE,
        }

        result = 0
        for pf, prot in mapping.items():
            if flags & pf:
                result |= prot

        return result


class MAP(enum.IntFlag):
    SHARED = 0x01
    PRIVATE = 0x02
    FIXED = 0x10
    ANONYMOUS = 0x20


class AT(enum.IntEnum):
    NULL = 0
    IGNORE = 1
    EXECFD = 2
    PHDR = 3
    PHENT = 4
    PHNUM = 5
    PAGESZ = 6
    BASE = 7
    FLAGS = 8
    ENTRY = 9
    NOTELF = 10
    UID = 11
    EUID = 12
    GID = 13
    EGID = 14
    PLATFORM = 15
    HWCAP = 16
    CLKTCK = 17
    SECURE = 23
    BASE_PLATFORM = 24
    RANDOM = 25
    EXECFN = 31
    SYSINFO = 32
    SYSINFO_EHDR = 33


PAGE_SIZE = 4096
ALIGN = PAGE_SIZE - 1


libc = None
loader = None


def _setup_libc(path: str | None = None) -> None:
    """Set up the libc functions.

    Args:
        path: The optional path to the libc library to use.
    """
    path = path or ctypes.util.find_library("c")
    if path is None:
        raise ValueError("Unable to find path to libc")

    global libc
    if libc is not None:
        return

    libc = ctypes.CDLL(path, use_errno=True)

    libc.mmap.argtypes = [
        # addr
        ctypes.c_size_t,
        # length
        ctypes.c_size_t,
        # prot
        ctypes.c_int,
        # flags
        ctypes.c_int,
        # fd
        ctypes.c_int,
        # offset
        ctypes.c_size_t,
    ]
    libc.mmap.restype = ctypes.c_size_t

    libc.mprotect.argtypes = [
        # addr
        ctypes.c_size_t,
        # len
        ctypes.c_size_t,
        # prot
        ctypes.c_int,
    ]
    libc.mprotect.restype = ctypes.c_int

    libc.getauxval.argtypes = [
        # type
        ctypes.c_ulong
    ]
    libc.getauxval.restype = ctypes.c_size_t

    if log.level <= logging.DEBUG:
        libc.mmap = _ctype_log(libc.mmap)
        libc.mprotect = _ctype_log(libc.mprotect)
        libc.getauxval = _ctype_log(libc.getauxval)


def _setup_loader() -> None:
    """Set up the loader function."""
    global loader
    if loader is not None:
        return

    machine = platform.machine()
    if machine == "x86_64":
        asm = bytes.fromhex(
            # rdi = pointer to initial stack
            # rsi = size of stack
            # rdx = entry point
            #
            # Reserve space for the stack and align it
            "   48 29 f4"  # sub rsp, rsi
            "48 83 e4 f0"  # and rsp, 0fffffffffffffff0h
            # Copy the stack over (dst=rdi, src=rsi, count=rcx)
            "   48 89 f1"  # mov rcx, rsi
            "   48 89 fe"  # mov rsi, rdi
            "   48 89 e7"  # mov rdi, rsp
            "         fc"  # cld
            "      f3 a4"  # rep movsb
            # Jump to the entry point
            "      ff e2"  # jmp rdx
            "         f4"  # hlt
        )
    elif machine == "aarch64":
        asm = bytes.fromhex(
            # x0 = pointer to initial stack
            # x1 = size of stack
            # x2 = entry point
            #
            # Reserve space for the stack and align it
            "eb 63 21 cb"  # sub x11, sp, x1
            "6b ed 7c 92"  # and x11, x11, #~0xF
            "7f 01 00 91"  # mov sp, x11
            # Copy the stack over (dst=x3, src=x0, count=x1)
            "e3 03 00 91"  # mov x3, sp
            "a1 00 00 b4"  # loop: cbz x1, end
            "06 14 40 38"  # ldrb w6, [x0], #1
            "66 14 00 38"  # strb w6, [x3], #1
            "21 04 00 f1"  # subs x1, x1, #1
            "81 ff ff 54"  # b.ne loop
            # Jump to the entry point
            "40 00 1f d6"  # end: br x2
        )
    else:
        raise NotImplementedError(f"Unsupported architecture: {machine}")

    buf = libc.mmap(0, len(asm), PROT.WRITE, MAP.PRIVATE | MAP.ANONYMOUS, -1, 0)
    ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_char * len(asm)))
    ptr.contents[:] = asm
    libc.mprotect(buf, len(asm), PROT.READ | PROT.EXEC)

    loader = ctypes.cast(
        buf,
        ctypes.CFUNCTYPE(
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_size_t,
        ),
    )

    if log.level <= logging.DEBUG:
        loader = _ctype_log(loader)


def _ctype_log(function: Callable) -> Callable:
    def fmt(arg: Any) -> str:
        if isinstance(arg, enum.Enum):
            return f"{arg.__class__.__name__}_{arg.name}"
        if isinstance(arg, int):
            return hex(arg)
        return repr(arg)

    def wrapper(*args, **kwargs) -> Any:
        result = function(*args, **kwargs)
        arg_str = ", ".join(f"{fmt(arg)}" for arg in args)
        log.debug("%s(%s) -> %s", function.__name__, arg_str, fmt(result))
        return result

    return wrapper


def load(
    elf: Path | bytes | BinaryIO,
    argv: list[str] | None = None,
    env: dict[str, str] | None = None,
    *,
    libc: str | None = None,
) -> None:
    """Load an ELF executable into memory and execute it.

    Args:
        elf: The path to the ELF executable or the ELF data to load.
        argv: The arguments to pass to the executable.
        env: The environment variables to pass to the executable.
        libc: The optional path to the libc library to use.
    """
    if os.name != "posix" and sys.platform != "darwin":
        raise TypeError("This loader only supports POSIX systems")

    _setup_libc(libc)
    _setup_loader()

    argv = argv or []
    env = env or {}

    if isinstance(elf, Path):
        fh = elf.open("rb")
    else:
        fh = contextlib.nullcontext(BytesIO(elf)) if isinstance(elf, bytes) else elf

    with fh:
        elf = ELF(fh)

        if elf.dynamic:
            raise NotImplementedError("Dynamic loading is not yet implemented, only static executables are supported")

        segments = elf.segments.by_type(PT.LOAD)
        base = truncate(min([s.virtual_address for s in segments]))

        for segment in segments:
            map_segment(segment, MAP.FIXED | MAP.PRIVATE | MAP.ANONYMOUS)

        stack = create_stack(elf, base, argv, env)
        loader(stack, len(stack), elf.header.e_entry)


def map_segment(segment: Segment, flags: MAP) -> None:
    """Map segment to memory.

    Args:
        segment: The segment to map.
        flags: The flags to pass to mmap.
    """
    alignment = segment.alignment - 1

    offset = segment.virtual_address & alignment
    start = truncate(segment.virtual_address, alignment)
    size = round(segment.memory_size + offset, alignment)

    pointer = libc.mmap(start, size, PROT.WRITE, flags, -1, 0)

    if pointer == 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("mmap failed to allocate memory.")

    ptr = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_char * size))
    ptr.contents[offset : offset + segment.size] = segment.data

    pflags = PROT.from_PF(segment.flags)
    libc.mprotect(pointer, size, pflags)


def create_stack(elf: ELF, base: int, argv: list[str], env: dict[str, str]) -> bytes:
    """Create the initial process stack for the executable.

    The stack is created according to the System V AMD64 ABI specification, which can be found here:
    https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf

    Args:
        elf: The ELF executable to create the stack for.
        base: The base address of the executable.
        argv: The arguments to pass to the executable.
        env: The environment variables to pass to the executable.
    """
    stack = BytesIO()

    stack.write(struct.pack("<Q", len(argv)))

    c_argv = (ctypes.c_char_p * len(argv))(*[s.encode() for s in argv])
    stack.write(c_argv)
    stack.write(ctypes.c_void_p())

    c_envp = (ctypes.c_char_p * len(env))(*[f"{k}={v}".encode() for k, v in env.items()])
    stack.write(c_envp)
    stack.write(ctypes.c_void_p())

    copy_aux(stack, AT.SYSINFO_EHDR)
    copy_aux(stack, AT.HWCAP)
    copy_aux(stack, AT.PAGESZ)
    copy_aux(stack, AT.CLKTCK)
    write_aux(stack, AT.PHDR, ctypes.c_size_t(base + elf.header.e_phoff))
    write_aux(stack, AT.PHENT, ctypes.c_size_t(elf.header.e_phentsize))
    write_aux(stack, AT.PHNUM, ctypes.c_size_t(elf.header.e_phnum))
    write_aux(stack, AT.BASE, ctypes.c_size_t(0))
    write_aux(stack, AT.FLAGS, ctypes.c_size_t(0))
    write_aux(stack, AT.ENTRY, ctypes.c_size_t(elf.header.e_entry))
    copy_aux(stack, AT.UID)
    copy_aux(stack, AT.EUID)
    copy_aux(stack, AT.GID)
    copy_aux(stack, AT.EGID)
    copy_aux(stack, AT.SECURE)
    write_aux(stack, AT.RANDOM, ctypes.c_char_p(random.randbytes(16)))
    write_aux(stack, AT.EXECFN, ctypes.c_char_p(c_argv[0]))
    write_aux(stack, AT.PLATFORM, ctypes.c_char_p(platform.machine().encode() + b"\x00"))
    write_aux(stack, AT.NULL, ctypes.c_size_t(0))

    return stack.getvalue()


def copy_aux(fh: BinaryIO, type: AT) -> None:
    """Copy auxiliary value from the host process to the stack."""
    write_aux(fh, type, ctypes.c_uint64(libc.getauxval(type)))


def write_aux(fh: BinaryIO, type: AT, value: bytes) -> None:
    """Write auxiliary value to the stack."""
    fh.write(struct.pack("<Q", type))
    fh.write(value)


def truncate(value: int, align: int = ALIGN) -> int:
    """Truncate value to alignment."""
    return value & ~(align)


def round(value: int, align: int = ALIGN) -> int:
    """Round value up to alignment."""
    return truncate(value + align, align)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path, help="the ELF executable to load")
    parser.add_argument("--libc", type=str, help="the path of the libc library to use")
    parser.add_argument(
        "--env", "-e", type=json.loads, default=None, help="environment variables to pass to the executable"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose logging")
    args, rest = parser.parse_known_args()

    if args.verbose:
        logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
        log.setLevel(logging.DEBUG)

    arguments = [args.path.name, *rest]
    load(args.path, arguments, args.env, libc=args.libc)


if __name__ == "__main__":
    main()
