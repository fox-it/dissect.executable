from __future__ import annotations

from functools import cached_property
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO, Union

from dissect.util.ts import from_unix, wintimestamp

try:
    from typing import TypeAlias  # novermin
except ImportError:
    # COMPAT: Remove this when we drop Python 3.9
    TypeAlias = Any


from dissect.util.stream import RangeStream

from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.directory.base import DataDirectory
from dissect.executable.pe.locale_id import CP_TO_NAME, LCID_TO_TAG, TAG_TO_LCID

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterator

    from dissect.executable.pe.pe import PE


class ResourceDirectory(DataDirectory):
    """The resource directory of a PE file.

    This class provides a higher-level interface to access resources in a PE file. If you wish to access
    the raw resource directory structure, you can traverse it with the ``tree`` attribute.
    """

    def __init__(self, pe: PE, address: int, size: int):
        super().__init__(pe, address, size)
        self.tree = ResourceDirectoryEntry(self, address)

    def __repr__(self) -> str:
        return f"<ResourceDirectory resources={len(self.resources)}>"

    def __len__(self) -> int:
        return len(self.resources)

    def __iter__(self) -> Iterator[Resource]:
        return iter(self.resources)

    def __getitem__(self, idx: int | str | c_pe.RT) -> list[Resource] | None:
        """Get a resource by index or type.

        Args:
            idx: The index of the resource to get, which can be an integer, a string (resource type name),
                 or a member of the ``c_pe.RT`` enum. Integers refer to the index in the resources list,
                 while strings and enum members refer to the resource type.
        """
        if isinstance(idx, int):
            return self.resources[idx]

        if isinstance(idx, (str, c_pe.RT)):
            return self.get(idx)

        raise TypeError(f"ResourceDirectory indices must be int, str or RT enum members, not {type(idx).__name__}")

    def __contains__(self, idx: str | c_pe.RT) -> bool:
        if isinstance(idx, (str, c_pe.RT)):
            return self.get(idx) is not None

        return False

    def get(self, type: int | str | c_pe.RT) -> list[Resource] | None:
        """Get all resources of a specific type.

        Args:
            type: The type of the resource (e.g. ``c_pe.RT.ICON``).
                  Integers can also be used to refer to resource types by their numeric value,
                  or strings to refer to resource types by their name.
        """
        if isinstance(type, int):
            type = c_pe.RT(type)

        if isinstance(type, str) and type in c_pe.RT.__members__:
            type = c_pe.RT[type]

        if (root := self.tree.get(type)) is None:
            return None

        return [Resource(type, name, entry) for name, entry in root.iterdir()]

    def find(self, type: int | str | c_pe.RT, name: str | int) -> Resource | None:
        """Find a specific resource by type and name.

        Args:
            type: The type of the resource (e.g. ``c_pe.RT.ICON``).
                  Integers can also be used to refer to resource types by their numeric value,
                  or strings to refer to resource types by their name.
            name: The name of the resource, which can be a string or an integer ID.
        """
        if isinstance(type, int):
            type = c_pe.RT(type)

        if isinstance(type, str) and type in c_pe.RT.__members__:
            type = c_pe.RT[type]

        if (root := self.tree.get(type)) is None:
            return None

        if isinstance(name, str):
            name = TAG_TO_LCID.get(name, name)

        if isinstance(name, (int, c_pe.RT)) and (entry := root.get(name)) is not None:
            return Resource(type, name, entry)

        raise KeyError(f"Resource with type {type.name!r} and name {name!r} not found")

    @cached_property
    def resources(self) -> list[Resource]:
        """Return a list of all resources."""
        result = []

        for type, type_entry in self.tree.iterdir():
            for name, entry in type_entry.iterdir():
                result.append(Resource(c_pe.RT(type) if isinstance(type, int) else type, name, entry))

        return result

    @property
    def cursor(self) -> list[Resource] | None:
        """Return a list of hardware-dependent cursor resources, if available."""
        return self.get(c_pe.RT.CURSOR)

    @property
    def bitmap(self) -> list[Resource] | None:
        """Return a list of bitmap resources, if available."""
        return self.get(c_pe.RT.BITMAP)

    @property
    def icon(self) -> list[Resource] | None:
        """Return a list of hardware-dependent icon resources, if available."""
        return self.get(c_pe.RT.ICON)

    @property
    def menu(self) -> list[Resource] | None:
        """Return a list of menu resources, if available."""
        return self.get(c_pe.RT.MENU)

    @property
    def dialog(self) -> list[Resource] | None:
        """Return a list of dialog box resources, if available."""
        return self.get(c_pe.RT.DIALOG)

    @property
    def string(self) -> list[Resource] | None:
        """Return a list of string table resources, if available."""
        return self.get(c_pe.RT.STRING)

    def string_table(self, language: str | int | None = None) -> dict[int, str]:
        """Return the parsed string table for a specific language.

        Args:
            language: The language of the string table to return.
                      If ``None``, the first available language is used.
        """
        result = {}

        if isinstance(language, str):
            language = TAG_TO_LCID.get(language, language)

        root = self.tree.get(c_pe.RT.STRING)

        for id, resource in root.iterdir():
            idx = (id - 1) * 16
            entry = next(resource.iterdir())[1] if language is None else resource.get(language)

            with entry.open() as fh:
                while fh.tell() != entry.size:
                    if length := c_pe.USHORT(fh):
                        result[idx] = fh.read(length * 2).decode("utf-16-le")
                    idx += 1

        return result

    @property
    def fontdir(self) -> list[Resource] | None:
        """Return a list of font directory resources, if available."""
        return self.get(c_pe.RT.FONTDIR)

    @property
    def font(self) -> list[Resource] | None:
        """Return a list of font resources, if available."""
        return self.get(c_pe.RT.FONT)

    @property
    def accelerator(self) -> list[Resource] | None:
        """Return a list of accelerator table resources, if available."""
        return self.get(c_pe.RT.ACCELERATOR)

    def accelerator_table(self, language: str | int | None = None) -> dict[int, str]:
        """Return the parsed accelerator table for a specific language.

        Args:
            language: The language of the version information to return.
                      If ``None``, the first available language is used.
        """
        result = []

        if isinstance(language, str):
            language = TAG_TO_LCID.get(language, language)

        for accelerator in self.accelerator or []:
            with accelerator.open(language) as fh:
                last_found = False
                while not last_found:
                    try:
                        key_flags = c_pe.ULONG(fh)
                        modifiers = c_pe.ACCEL_F(key_flags & 0xFFFF)
                        key = c_pe.VK(key_flags >> 16)
                        cmd = c_pe.ULONG(fh)

                        if c_pe.ACCEL_F.LASTKEY in modifiers:
                            last_found = True
                            modifiers &= ~c_pe.ACCEL_F.LASTKEY

                        result.append((key, cmd & 0xFFFF, modifiers))
                    except EOFError:  # noqa: PERF203
                        break

        return result

    @property
    def rcdata(self) -> list[Resource] | None:
        """Return a list of application-defined (raw data) resources, if available."""
        return self.get(c_pe.RT.RCDATA)

    @property
    def message_table(self) -> list[Resource] | None:
        """Return a list of message table resources, if available."""
        return self.get(c_pe.RT.MESSAGETABLE)

    @property
    def group_cursor(self) -> list[Resource] | None:
        """Return a list of hardware-independent group cursor resources, if available."""
        return self.get(c_pe.RT.GROUP_CURSOR)

    @property
    def group_icon(self) -> list[Resource] | None:
        """Return a list of hardware-independent group icon resources, if available."""
        return self.get(c_pe.RT.GROUP_ICON)

    @property
    def version(self) -> list[Resource] | None:
        """Return a list of version resources, if available."""
        return self.get(c_pe.RT.VERSION)

    def vs_version_info(self, language: str | int | None = None) -> dict | None:
        """Return the parsed version information for a specific language.

        Args:
            language: The language of the version information to return.
                      If ``None``, the first available language is used.
        """
        if isinstance(language, str):
            language = TAG_TO_LCID.get(language, language)

        if not (version := self.get(c_pe.RT.VERSION)):
            return None

        if len(version) != 1:
            raise ValueError(f"Expected exactly one version resource, found {len(version)}")

        _Node: TypeAlias = tuple[str, Union[str, bytes, None], list["_Node"]]

        def _parse_lvt(fh: BinaryIO) -> _Node | None:
            start = fh.tell()
            length = c_pe.USHORT(fh)
            if length == 0:
                return None

            value_length = c_pe.USHORT(fh)
            value_type = c_pe.USHORT(fh)

            key = c_pe.WCHAR[None](fh).rstrip("\x00")
            fh.seek(fh.tell() + (-fh.tell() & 3))  # Align to 4 bytes
            value = None
            if value_length:
                value = (
                    fh.read(value_length * 2).decode("utf-16-le").rstrip("\x00")
                    if value_type == 1
                    else fh.read(value_length)
                )
            fh.seek(fh.tell() + (-fh.tell() & 3))  # Align to 4 bytes

            children = []
            while fh.tell() - start < length:
                if (child := _parse_lvt(fh)) is None:
                    break
                children.append(child)

            return key, value, children

        def _build_dict(node: _Node, obj: dict[str, Any]) -> None:
            key, value, children = node

            if key == "VS_VERSION_INFO":
                # Special case for VS_VERSION_INFO, which is a top-level key
                obj[key] = {}
                file_info = c_pe.VS_FIXEDFILEINFO(value.ljust(len(c_pe.VS_FIXEDFILEINFO), b"\x00"))
                if file_info.dwSignature != 0xFEEF04BD:
                    raise ValueError("Invalid VS_FIXEDFILEINFO signature")

                if file_info.dwFileVersionMS or file_info.dwFileVersionLS:
                    obj[key]["FileVersion"] = (
                        f"{file_info.dwFileVersionMS >> 16}.{file_info.dwFileVersionMS & 0xFFFF}.{file_info.dwFileVersionLS >> 16}.{file_info.dwFileVersionLS & 0xFFFF}"  # noqa: E501
                    )

                if file_info.dwProductVersionMS or file_info.dwProductVersionLS:
                    obj[key]["ProductVersion"] = (
                        f"{file_info.dwProductVersionMS >> 16}.{file_info.dwProductVersionMS & 0xFFFF}.{file_info.dwProductVersionLS >> 16}.{file_info.dwProductVersionLS & 0xFFFF}"  # noqa: E501
                    )

                if file_info.dwFileFlags:
                    obj[key]["FileFlags"] = c_pe.VS_FF(file_info.dwFileFlags & file_info.dwFileFlagsMask).name

                if file_info.dwFileOS:
                    upper_file_os = file_info.dwFileOS & 0xFFFF0000
                    lower_file_os = file_info.dwFileOS & 0x0000FFFF
                    obj[key]["FileOS"] = "_".join(
                        c_pe.VOS(x).name for x in filter(None, [upper_file_os, lower_file_os])
                    )

                if file_info.dwFileType:
                    obj[key]["FileType"] = c_pe.VFT(file_info.dwFileType).name

                    if file_info.dwFileSubtype:
                        if file_info.dwFileType == c_pe.VFT.DRV:
                            obj[key]["FileSubtype"] = c_pe.VFT2_DRV(file_info.dwFileSubtype).name
                        elif file_info.dwFileType == c_pe.VFT.FONT:
                            obj[key]["FileSubtype"] = c_pe.VFT2_FONT(file_info.dwFileSubtype).name
                        else:
                            obj[key]["FileSubtype"] = file_info.dwFileSubtype

                if file_info.dwFileDateMS or file_info.dwFileDateLS:
                    obj[key]["FileDate"] = wintimestamp(file_info.dwFileDateMS << 32 | file_info.dwFileDateLS)
            else:
                if value is not None:
                    obj[key] = value
                else:
                    obj[key] = {}

            for child in children:
                _build_dict(child, obj[key])

        result = {}
        with version[0].open(language) as fh:
            _build_dict(_parse_lvt(fh), result)

        if sfi := result.get("VS_VERSION_INFO", {}).get("StringFileInfo", {}):
            keys = list(sfi.keys())
            for key in keys:
                lcid = int(key[:4], 16)
                codepage = int(key[4:], 16)
                sfi[f"{LCID_TO_TAG.get(lcid, str(lcid))}_{CP_TO_NAME.get(codepage, str(codepage))}"] = sfi[key]
                del sfi[key]

        if (vfit := result.get("VS_VERSION_INFO", {}).get("VarFileInfo", {})) and "Translation" in vfit:
            buf = BytesIO(vfit["Translation"])
            tmp = []
            for _ in range(len(vfit["Translation"]) // 4):
                lcid, codepage = c_pe.USHORT[2](buf)
                tmp.append(f"{LCID_TO_TAG.get(lcid, str(lcid))}_{CP_TO_NAME.get(codepage, str(codepage))}")
            vfit["Translation"] = tmp

        return result

    @property
    def dialog_include(self) -> list[Resource] | None:
        """Return a list of dialog include resources, if available."""
        return self.get(c_pe.RT.DLGINCLUDE)

    @property
    def plug_and_play(self) -> list[Resource] | None:
        """Return a list of plug and play resources, if available."""
        return self.get(c_pe.RT.PLUGPLAY)

    @property
    def vxd(self) -> list[Resource] | None:
        """Return a list of VXD resources, if available."""
        return self.get(c_pe.RT.VXD)

    @property
    def animated_cursor(self) -> list[Resource] | None:
        """Return a list of animated cursor resources, if available."""
        return self.get(c_pe.RT.ANICURSOR)

    @property
    def animated_icon(self) -> list[Resource] | None:
        """Return a list of animated icon resources, if available."""
        return self.get(c_pe.RT.ANIICON)

    @property
    def html(self) -> list[Resource] | None:
        """Return a list of HTML resources, if available."""
        return self.get(c_pe.RT.HTML)

    @property
    def manifest(self) -> list[Resource] | None:
        """Return a list of side-by-side assembly manifest resources, if available."""
        return self.get(c_pe.RT.MANIFEST)


class Resource:
    """Higher level representation of a resource in a PE file.

    This class provides a convenient interface to access resource data, abstracting away the details of the
    underlying resource directory structure.

    Args:
        type: The type of the resource (e.g. ``c_pe.RT.ICON``).
        name: The name of the resource, which can be a string or an integer ID.
        entry: The resource directory entry that contains the resource data per language.
    """

    def __init__(self, type: c_pe.RT | str, name: str | int, entry: ResourceDirectoryEntry):
        self.type = type
        self.name = name
        self.entry = entry

    def __repr__(self) -> str:
        return f"<Resource type={self.type!s} name={self.name!r}>"

    def __iter__(self) -> Iterator[Resource]:
        return self.entry.iterdir()

    def __getitem__(self, idx: int | str) -> ResourceDataEntry:
        """Get a specific resource data entry by language.

        Args:
            idx: The index of the resource data entry, which can be an integer (LCID) or a string (language tag).
        """
        if isinstance(idx, str):
            idx = TAG_TO_LCID.get(idx, idx)

        if isinstance(idx, int) and (entry := self.entry.get(idx)) is not None:
            return entry

        raise KeyError(f"Resource with language {idx!r} not found in {self!r}")

    def __contains__(self, idx: str | c_pe.RT) -> bool:
        if isinstance(idx, str):
            idx = TAG_TO_LCID.get(idx, idx)

        if isinstance(idx, int):
            return self.entry.get(idx) is not None

        return False

    def languages(self) -> list[str]:
        """Return a list of languages for this resource."""
        return [LCID_TO_TAG.get(name, str(name)) for name, _ in self.entry.iterdir()]

    def data(self, language: str | int | None = None) -> bytes:
        """Get the resource data for a specific language.

        Args:
            language: The language of the resource to open. If ``None``, the first available resource is opened.
        """
        with self.open(language) as fh:
            return fh.read()

    def open(self, language: str | int | None = None) -> RangeStream:
        """Open the resource data as a stream.

        Args:
            language: The language of the resource to open. If ``None``, the first available resource is opened.
        """
        if language is None:
            return next(self.entry.iterdir())[1].open()

        if isinstance(language, str):
            language = TAG_TO_LCID.get(language, language)

        if isinstance(language, int) and (entry := self.entry.get(language)) is not None:
            return entry.open()

        raise KeyError(f"Resource with language {language!r} not found in {self!r}")


class ResourceEntry:
    """Base class for resource entries in a PE file."""

    def __init__(self, rsrc: ResourceDirectory, address: int):
        self.rsrc = rsrc
        self.address = address

    @cached_property
    def entry(self) -> c_pe.IMAGE_RESOURCE_DATA_ENTRY:
        raise NotImplementedError


class ResourceDataEntry(ResourceEntry):
    """A resource data entry in a PE file."""

    def __repr__(self) -> str:
        return f"<ResourceDataEntry address={self.address:#x} size={self.size} code_page={self.code_page}>"

    @cached_property
    def entry(self) -> c_pe.IMAGE_RESOURCE_DATA_ENTRY:
        """The resource data entry structure."""
        self.rsrc.pe.vfh.seek(self.address)
        return c_pe.IMAGE_RESOURCE_DATA_ENTRY(self.rsrc.pe.vfh)

    @property
    def offset_to_data(self) -> int:
        """The offset to the resource data in the file."""
        return self.entry.OffsetToData

    @property
    def size(self) -> int:
        """The size of the resource data."""
        return self.entry.Size

    @property
    def code_page(self) -> int:
        """The code page of the resource data."""
        return self.entry.CodePage

    @property
    def data(self) -> bytes:
        """The raw resource data."""
        self.rsrc.pe.vfh.seek(self.offset_to_data)
        return self.rsrc.pe.vfh.read(self.size)

    def open(self) -> RangeStream:
        """Open the resource data as a stream."""
        return RangeStream(self.rsrc.pe.vfh, self.offset_to_data, self.size)


class ResourceDirectoryEntry(ResourceEntry):
    """A resource directory entry in a PE file."""

    def __repr__(self) -> str:
        return f"<ResourceDirectoryEntry address={self.address:#x} entries={self.entry.NumberOfNamedEntries + self.entry.NumberOfIdEntries}>"  # noqa: E501

    @cached_property
    def entry(self) -> c_pe.IMAGE_RESOURCE_DIRECTORY:
        """The resource directory entry structure."""
        self.rsrc.pe.vfh.seek(self.address)
        return c_pe.IMAGE_RESOURCE_DIRECTORY(self.rsrc.pe.vfh)

    @property
    def timestamp(self) -> datetime.datetime | None:
        """The timestamp of this resource directory, or ``None`` if the PE file is compiled as reproducible."""
        if self.rsrc.pe.is_reproducible():
            return None
        return from_unix(self.entry.TimeDateStamp)

    def get(self, name: int | str | c_pe.RT) -> ResourceDataEntry | ResourceDirectoryEntry | None:
        """Get a resource entry by name."""
        for id, entry in self.iterdir():
            if id == name:
                return entry
        return None

    def listdir(self) -> dict[int | str, ResourceEntry]:
        """Return a dictionary of the entries in this resource directory."""
        return dict(self.iterdir())

    def iterdir(self) -> Iterator[tuple[int | str, ResourceDataEntry | ResourceDirectoryEntry]]:
        """Iterate over the entries in this resource directory."""
        vfh = self.rsrc.pe.vfh
        offset = self.address + len(c_pe.IMAGE_RESOURCE_DIRECTORY)
        for _ in range(self.entry.NumberOfNamedEntries + self.entry.NumberOfIdEntries):
            vfh.seek(offset)
            entry = c_pe.IMAGE_RESOURCE_DIRECTORY_ENTRY(vfh)

            if entry.NameIsString:
                vfh.seek(self.rsrc.address + entry.NameOffset)
                name = c_pe.IMAGE_RESOURCE_DIR_STRING_U(vfh).NameString
            else:
                name = entry.Id

            if entry.DataIsDirectory:
                obj = ResourceDirectoryEntry(self.rsrc, self.rsrc.address + entry.OffsetToDirectory)
            else:
                obj = ResourceDataEntry(self.rsrc, self.rsrc.address + entry.OffsetToData)

            yield name, obj

            offset += len(c_pe.IMAGE_RESOURCE_DIRECTORY_ENTRY)
