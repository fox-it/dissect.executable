from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from functools import partial
from io import BytesIO
from itertools import chain
from textwrap import indent
from typing import TYPE_CHECKING

from dissect.executable.exception import ResourceException
from dissect.executable.pe.c_pe import c_pe
from dissect.executable.pe.helpers.utils import DictManager

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import BinaryIO, Callable

    from dissect.executable.pe.helpers.sections import PESection
    from dissect.executable.pe.pe import PE


@dataclass
class RawResource:
    offset: int
    entry: c_pe.IMAGE_RESOURCE_DIRECTORY_ENTRY | c_pe.IMAGE_RESOURCE_DIRECTORY | c_pe.IMAGE_RESOURCE_DATA_ENTRY
    data_offset: int
    data: bytes | None = None
    resource: Resource | None = None


def rc_type_name(entry: c_pe.IMAGE_RESOURCE_DIRECTORY_ENTRY, data: BinaryIO, depth: int = 1) -> str:
    """Returns the name of the rc type depending on the data and the depth level of the resource"""
    if depth == 1:
        return c_pe.ResourceID(entry.Id).name

    if entry.NameIsString:
        data.seek(entry.NameOffset)
        name_len = c_pe.uint16(data)
        return c_pe.wchar[name_len](data)

    return str(entry.Id)


class ResourceManager(DictManager["Resource"]):
    """Base class to perform actions regarding the resources within the PE file.

    Args:
        pe: A `PE` object.
        section: The section object that contains the resource table.
    """

    def __init__(self, pe: PE, section: PESection):
        super().__init__(pe, section)
        self.elements: OrderedDict[str, Resource] = OrderedDict()
        self.raw_resources: list[RawResource] = []
        self.values = partial(self._resources, self.elements)
        self.parse()

    def parse(self) -> None:
        """Parse the resource directory entry of the PE file."""

        rsrc_data = BytesIO(self.section.directory_data(c_pe.IMAGE_DIRECTORY_ENTRY_RESOURCE))
        self.elements = self._read_resource(data=rsrc_data, offset=0)

    def patch(self, name: str, data: bytes) -> None:
        """Sets the new data of the resource and updates the offsets with the resources within the same directory.

        Resource looks like this:

        | Resource headers (1*...) |
        | ------------------------ |
        | Resource data (1*...)    |

        So it is not important in what order the metadata of the entry gets written.
        """
        try:
            resource = next(self.by_type(name))
        except StopIteration:
            raise ValueError(f"Could not find a resource by type for {name}")

        # TODO: Still rewrites the data to the original instance. Maybe we should change that.
        resource._data = data
        resource.size = len(data)

        output = BytesIO()
        prev_offset = prev_size = 0

        for rsrc_entry in self.raw(lambda rsrc: rsrc.data_offset):
            entry_offset = rsrc_entry.offset
            entry = rsrc_entry.entry

            # Write the resource entry into the section
            output.seek(entry_offset)
            output.write(entry.dumps())

            if not isinstance(entry, c_pe.IMAGE_RESOURCE_DATA_ENTRY):
                continue

            rsrc_obj = rsrc_entry.resource
            data_offset = rsrc_entry.data_offset

            # Normally the data is separated by a null byte, increment the new offset by 1
            new_data_offset = prev_offset + prev_size
            # if new_data_offset and (new_data_offset > data_offset or new_data_offset < data_offset):
            if new_data_offset and new_data_offset != data_offset:
                data_offset = new_data_offset
                rsrc_entry.data_offset = data_offset
                rsrc_obj.offset = self.section.virtual_address + data_offset

            # Write the resource entry data into the section
            output.seek(data_offset)
            output.write(rsrc_obj.data)

            # Take note of the offset and size so we can update any of these values after changing the data within
            # the resource
            prev_offset = data_offset
            prev_size = rsrc_obj.size

        output.seek(0)
        _data = output.read()

        self.pe.sections.patch(self.section.name, _data)
        self.pe.optional_header.DataDirectory[c_pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].size = len(_data)

    def _read_entries(
        self, data: BinaryIO, directory: c_pe.IMAGE_RESOURCE_DIRECTORY
    ) -> list[c_pe.IMAGE_RESOURCE_DIRECTORY_ENTRY]:
        """Read the entries within the resource directory.

        Args:
            data: The data of the resource directory.
            directory: The resource directory entry.

        Returns:
            A list containing the entries of the resource directory.
        """

        entries = []
        for _ in range(directory.NumberOfNamedEntries + directory.NumberOfIdEntries):
            entry_offset = data.tell()
            entry = c_pe.IMAGE_RESOURCE_DIRECTORY_ENTRY(data)
            self.raw_resources.append(
                RawResource(
                    offset=entry_offset,
                    entry=entry,
                    data_offset=entry_offset,
                )
            )
            entries.append(entry)
        return entries

    def _handle_data_entry(self, data: BinaryIO, entry: c_pe.IMAGE_RESOURCE_DIRECTORY_ENTRY, rc_type: str) -> Resource:
        """Handle the data entry of a resource. This is the actual data associated with the directory entry.

        Args:
            data: The data of the resource.
            entry: The resource directory entry.

        Returns:
            The resource that was given by name as a `Resource` object.
        """

        data.seek(entry.OffsetToDirectory)
        data_entry = c_pe.IMAGE_RESOURCE_DATA_ENTRY(data)
        self.pe.seek(data_entry.OffsetToData)
        _data = self.pe.read(data_entry.Size)
        raw_offset = data_entry.OffsetToData - self.section.virtual_address
        rsrc = Resource(
            pe=self.pe,
            section=self.section,
            name=entry.Name,
            entry_offset=entry.OffsetToData,
            data_entry=data_entry,
            rc_type=rc_type,
        )
        self.raw_resources.append(
            RawResource(
                offset=entry.OffsetToDirectory,
                entry=data_entry,
                data=_data,
                data_offset=raw_offset,
                resource=rsrc,
            )
        )
        return rsrc

    def _read_resource(self, data: BinaryIO, offset: int, depth: int = 1) -> OrderedDict[str, Resource]:
        """Recursively read the resources within the PE file.

        Each resource is added to the dictionary that is available to the user, as well as a list of
        raw resources that are used to update the section data and size when a resource has been modified.

        Args:
            data: The data of the resource.
            offset: The offset of the resource.
            depth: The depth level of the resource, this dictates the resource type.

        Returns:
            A dictionary containing the resources that were found.
        """

        resource = OrderedDict()

        data.seek(offset)
        directory = c_pe.IMAGE_RESOURCE_DIRECTORY(data)
        self.raw_resources.append(
            RawResource(
                offset=offset,
                entry=directory,
                data_offset=offset,
            )
        )

        for entry in self._read_entries(data, directory):
            rc_name = rc_type_name(entry, data, depth)

            if entry.DataIsDirectory:
                resource[rc_name] = self._read_resource(
                    data=data,
                    offset=entry.OffsetToDirectory,
                    depth=depth + 1,
                )
            else:
                resource[rc_name] = self._handle_data_entry(data=data, entry=entry, rc_type=rc_name)

        return resource

    def by_name(self, name: str) -> Resource | OrderedDict:
        """Retrieve the resource by name.

        Args:
            name: The name of the resource to retrieve.

        Returns:
            The resource that was given by name as a `Resource` object.
        """

        try:
            return self.elements[name]
        except KeyError:
            raise ResourceException(f"Resource {name} not found!")

    def by_type(self, rsrc_id: str | c_pe.ResourceID) -> Iterator[Resource]:
        """Yields a generator containing all of the nodes within the resources that contain the requested ID.

        The ID can be either given by name or its value.

        Args:
            rsrc_id: The resource ID to find, this can be a cstruct `EnumInstance` or `str`.

        Yields:
            All of the nodes that contain the requested type.
        """

        if rsrc_id not in self.elements:
            raise ResourceException(f"Resource with ID {rsrc_id} not found in PE!")

        yield from self._resources(resources=self.elements[rsrc_id])

    def _resources(self, resources: OrderedDict[str, Resource]) -> Iterator[Resource]:
        """Iterates throught the resources inside the PE file.

        Args:
            resources: A `dict` containing the different resources that were found.

        Yields:
            All of the resources within the PE file.
        """

        for resource in resources.values():
            if isinstance(resource, OrderedDict):
                yield from self._resources(resources=resource)
            else:
                yield resource

    def show_resource_tree(self, resources: OrderedDict[str, OrderedDict | Resource], indentation: int = 0) -> None:
        """Print the resources within the PE as a tree.

        Args:
            resources: A `dict` containing the different resources that were found.
            indent: The amount of indentation for each child resource.
        """

        for name, resource in resources.items():
            prefix = " " * indentation

            if isinstance(resource, OrderedDict):
                print(indent(f"+ name: {name}", prefix=prefix))
                self.show_resource_tree(resources=resource, indentation=indentation + 1)
            else:
                print(indent(f"- name: {name} ID: {resource.rsrc_id}", prefix=prefix))

    def show_resource_info(self, resources: dict) -> None:
        """Print basic information about the resource as well as the header.

        Args:
            resources: A `dict` containing the different resources that were found.
        """

        for name, resource in resources.items():
            if isinstance(resource, OrderedDict):
                self.show_resource_info(resources=resource)
            else:
                print(
                    f"* resource: {name} offset=0x{resource.offset:02x} size=0x{resource.size:02x} header: {resource.data[:64]}"  # noqa: E501
                )

    def raw(self, sort_key: Callable | None = None) -> Iterator[RawResource]:
        if sort_key:
            yield from sorted(self.raw_resources, key=sort_key)
        else:
            yield from self.raw_resources

    def update_section(self, update_offset: int) -> None:
        """Function to dynamically update the section data and size when a resource has been modified.

        Args:
            update_offset: The offset of the resource that was modified.
        """

        new_size = 0

        resource_iter = iter(self._resources(resources=self.elements))
        first_resource = next(resource_iter)

        header_size = first_resource.offset - self.section.virtual_address
        section_data = self.section.data[:header_size]

        for resource in chain([first_resource], resource_iter):
            # Update the resource data
            section_data += resource.data

            new_size += resource.size + 1  # Account for the id field

            # Skip the resources that are below our own offset
            if update_offset >= resource.offset:
                continue

            resource.offset = resource.offset + resource.size + 2

        # Add the header to the total size so we can check if we need to update the section size
        new_size += header_size

        self.pe.sections.patch(self.section.name, section_data)


class Resource:
    """Base class representing a resource entry in the PE file.

    Args:
        pe: A `PE` object.
        section: The section object that contains the resource table.
        name: The name of the resource.
        entry_offset: The offset of the resource entry.
        data_entry: The data entry of the resource.
        rc_type: The type of the resource.
        data: The data of the resource if there was data provided by the user.
    """

    def __init__(
        self,
        pe: PE,
        section: PESection,
        name: str | int,
        entry_offset: int,
        data_entry: c_pe.IMAGE_RESOURCE_DATA_ENTRY,
        rc_type: str,
        data: bytes = b"",
    ):
        self.pe = pe
        self.section = section
        self.name = name
        self.entry_offset = entry_offset
        self.entry = data_entry
        self.rc_type = rc_type
        self.offset = data_entry.OffsetToData
        self._size = data_entry.Size
        self.codepage = data_entry.CodePage
        self._data = data or self.read_data()

    def read_data(self) -> bytes:
        """Read the data within the resource.

        Returns:
            The resource data.
        """

        return self.pe.virtual_read(address=self.offset, size=self._size)

    @property
    def size(self) -> int:
        """Function to return the size of the resource.
        This needs to be done dynamically in the case that the data is patched by the user.

        Returns:
            The size of the data within the resource.
        """

        return len(self.data)

    @size.setter
    def size(self, value: int) -> None:
        """Setter to set the size of the resource to the specified value.

        Args:
            value: The size of the resource.
        """

        self._size = value
        self.entry.Size = value

    @property
    def offset(self) -> int:
        """Return the offset of the resource."""
        return self.entry.OffsetToData

    @offset.setter
    def offset(self, value: int) -> None:
        """Setter to set the offset of the resource to the specified value.

        Args:
            value: The offset of the resource.
        """

        self.entry.OffsetToData = value

    @property
    def data(self) -> bytes:
        """Return the data within the resource."""
        return self._data

    def __str__(self) -> str:
        return str(self.name)

    def __repr__(self) -> str:
        return f"<ResourceEntry name={self.name} id={self.rc_type} offset=0x{self.offset:02x} size=0x{self.size:02x} codepage=0x{self.codepage:02x}>"  # noqa: E501
