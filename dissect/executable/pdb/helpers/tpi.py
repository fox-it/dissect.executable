from __future__ import annotations

import os
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO, Iterable, Tuple

# External imports
from dissect.cstruct import Enum, Pointer, Structure, Union, cstruct

# Local imports
from dissect.executable.pdb.helpers.c_pdb import (
    ARCH_POINTERS,
    COMPILER_TYPES,
    POINTER_TYPES,
    c_pdb,
)
from dissect.executable.pdb.helpers.exception import UnknownTPIType

if TYPE_CHECKING:
    from dissect.executable.pdb.helpers.pagestream import PageStream

# Low effort type aliases
CType = "Any"
TypeObject = "Any"

# Default amount of bytes to skip when a numeric skip is performed for the type's name
DEFAULT_SKIP = 2


def skip_numeric(type_data: BinaryIO) -> int:
    """Implementation of the skipNumeric function in the official Microsoft PDB parsing code.

    This function is used to skip a certain amount of bytes for the variable length names in some
    of the structures and member fields of different types.

    Args:
        type_data: The TPI stream as a file-like object.

    Returns:
        The amount of bytes to skip.
    """

    index = c_pdb.uint16(type_data)
    if index < c_pdb.LEAF_ENUM_e.LF_NUMERIC.value:
        return DEFAULT_SKIP

    pnum = index + 1

    skip_values = {
        c_pdb.LEAF_ENUM_e.LF_CHAR.value: DEFAULT_SKIP + c_pdb.BYTE.size,
        c_pdb.LEAF_ENUM_e.LF_SHORT.value: DEFAULT_SKIP + c_pdb.SHORT.size,
        c_pdb.LEAF_ENUM_e.LF_USHORT.value: DEFAULT_SKIP + c_pdb.WORD.size,
        c_pdb.LEAF_ENUM_e.LF_LONG.value: DEFAULT_SKIP + 4,
        c_pdb.LEAF_ENUM_e.LF_ULONG.value: DEFAULT_SKIP + 4,
        c_pdb.LEAF_ENUM_e.LF_REAL32.value: DEFAULT_SKIP + 4,
        c_pdb.LEAF_ENUM_e.LF_REAL64.value: DEFAULT_SKIP + 8,
        c_pdb.LEAF_ENUM_e.LF_COMPLEX32.value: DEFAULT_SKIP + 8,
        c_pdb.LEAF_ENUM_e.LF_DATE.value: DEFAULT_SKIP + 8,
        c_pdb.LEAF_ENUM_e.LF_REAL80.value: DEFAULT_SKIP + 10,
        c_pdb.LEAF_ENUM_e.LF_QUADWORD.value: DEFAULT_SKIP + c_pdb.QWORD.size,
        c_pdb.LEAF_ENUM_e.LF_UQUADWORD.value: DEFAULT_SKIP + c_pdb.QWORD.size,
        c_pdb.LEAF_ENUM_e.LF_REAL48.value: DEFAULT_SKIP + 6,
        c_pdb.LEAF_ENUM_e.LF_COMPLEX64.value: DEFAULT_SKIP + 16,
        c_pdb.LEAF_ENUM_e.LF_OCTWORD.value: DEFAULT_SKIP + 16,
        c_pdb.LEAF_ENUM_e.LF_UOCTWORD.value: DEFAULT_SKIP + 16,
        c_pdb.LEAF_ENUM_e.LF_REAL128.value: DEFAULT_SKIP + 16,
        c_pdb.LEAF_ENUM_e.LF_COMPLEX80.value: DEFAULT_SKIP + 20,
        c_pdb.LEAF_ENUM_e.LF_COMPLEX128.value: DEFAULT_SKIP + 32,
        c_pdb.LEAF_ENUM_e.LF_VARSTRING.value: pnum + 4,
        # https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/data-type-summary
        c_pdb.LEAF_ENUM_e.LF_DECIMAL.value: DEFAULT_SKIP + 14,
        c_pdb.LEAF_ENUM_e.LF_UTF8STRING.value: DEFAULT_SKIP,
    }

    try:
        return skip_values[index]
    except KeyError:
        return DEFAULT_SKIP


def get_name(data: BinaryIO) -> str:
    """Retrieve the name of the member using the numeric skip that is used in PDB files.

    Args:
        data: The TPI stream as a file-like object.

    Returns:
        The name of the member as a string.
    """

    offset = data.tell()
    skip = skip_numeric(type_data=data)
    data.seek(offset + skip)
    name = c_pdb.char[None](data).decode()

    return name


class TPI:
    """Class for parsing the TPI stream of a PDB file.

    Args:
        streams: The list with `PageStream` entries for this PDB.
        pdb_cstruct: A `cstruct` instance that will be filled dynamically with the types defined in the TPI.
    """

    def __init__(self, streams: list[PageStream], pdb_cstruct: cstruct):
        self.tpi_stream = streams[2]
        self.pdb_cstruct = pdb_cstruct
        self.tpi_header = c_pdb.TpiHeader(self.tpi_stream)
        self.types = {}

    def parse_types(self):
        """Parse the types specificied in the TPI stream within the minimal and maximal type index values.

        When a type is parsed it is added to the types dictionary that can be used to parse the specific types as
        specified in the PDB.
        """

        for index in range(self.tpi_header.tiMin, self.tpi_header.tiMax):
            tpi = c_pdb.TpiType(self.tpi_stream)
            type_object = self._parse_type(index=index, tpi=tpi)
            self.types[index] = type_object

    def typedefs(self) -> cstruct:
        """Retrieve the PDB cstruct object containing the type definitions for further parsing.

        Returns:
            The PDB `cstruct` object.
        """
        return self.pdb_cstruct

    def _parse_type(self, index: int, tpi: cstruct) -> TypeObject:
        """Function to parse the TPI type by checking which type is checking out, adding it dynamically to the
        pdb_cstruct variable.

        Args:
            tpi: A `TpiType` structure definition specified in c_pdb.py.

        Returns:
            A `TypeObject` indicating the type that is associated with the specific index.

        Raises:
            `TPIShortEntry` when an entry shorter or equal to 2 bytes is encountered.
            `UnknownTPIType` if an unknown or unsupported yet TPI type is encountered.
        """

        if tpi.length <= 2:
            # This seems to happen sporadically but doesn't break the parsing?
            return

        type_data = BytesIO(tpi.type_data)
        tpi_type = c_pdb.uint16(type_data)
        tpi_type = c_pdb.LEAF_ENUM_e(tpi_type)

        try:
            resolve_tpi = {
                c_pdb.LEAF_ENUM_e.LF_MODIFIER: self._parse_lf_modifier,
                c_pdb.LEAF_ENUM_e.LF_PROCEDURE: self._parse_lf_procedure,
                c_pdb.LEAF_ENUM_e.LF_POINTER: self._parse_lf_pointer,
                c_pdb.LEAF_ENUM_e.LF_ARGLIST: self._parse_lf_arglist,
                c_pdb.LEAF_ENUM_e.LF_FIELDLIST: self._parse_lf_fieldlist,
                c_pdb.LEAF_ENUM_e.LF_BITFIELD: self._parse_lf_bitfield,
                c_pdb.LEAF_ENUM_e.LF_ARRAY: self._parse_lf_array,
                c_pdb.LEAF_ENUM_e.LF_STRUCTURE: self._parse_lf_structure,
                c_pdb.LEAF_ENUM_e.LF_STRUCTURE_16t: self._parse_lf_structure,
                c_pdb.LEAF_ENUM_e.LF_CLASS: self._parse_lf_structure,
                c_pdb.LEAF_ENUM_e.LF_CLASS_16t: self._parse_lf_structure,
                c_pdb.LEAF_ENUM_e.LF_UNION: self._parse_lf_union,
                c_pdb.LEAF_ENUM_e.LF_ENUM: self._parse_lf_enum,
                c_pdb.LEAF_ENUM_e.LF_MFUNCTION: self._parse_lf_mfunction,
                c_pdb.LEAF_ENUM_e.LF_MFUNCTION_16t: self._parse_lf_mfunction,
                c_pdb.LEAF_ENUM_e.LF_METHODLIST: self._parse_lf_methodlist,
                c_pdb.LEAF_ENUM_e.LF_METHODLIST_16t: self._parse_lf_methodlist,
                c_pdb.LEAF_ENUM_e.LF_VTSHAPE: self._parse_lf_vtshape,
                c_pdb.LEAF_ENUM_e.LF_VFTABLE: self._parse_lf_vftable,
            }
            return resolve_tpi[tpi_type](tpi_type=tpi_type, index=index, length=tpi.length, type_data=type_data)
        except KeyError:
            raise UnknownTPIType(f"Unsupported TPI: {tpi_type}")

    def _parse_lf_modifier(self, *args, **kwargs) -> Any:
        """Parser for the LF_MODIFIER leaf type.

        Returns:
            Type is dependent on the resolved type of the modifier.
        """

        # TODO
        mod = c_pdb.LF_MODIFIER(kwargs["type_data"])
        return self._resolve_type(mod.type)

    def _parse_lf_procedure(self, *args, **kwargs) -> cstruct:
        """Parser for the LF_PROCEDURE leaf type.

        Returns:
            A `cstruct` object containing the pointer sizetype for the leaf type.
        """

        # TODO
        # lf_proc = c_pdb.LF_PROCEDURE(kwargs["type_data"])
        # Better to return as a pointer as this can be parsed in structures
        return self.pdb_cstruct.ptr

    def _parse_lf_pointer(self, *args, **kwargs) -> Pointer:
        """Parser for the LF_POINTER leaf type.

        Returns:
            A `Pointer` object for the leaf type.
        """

        ptr = c_pdb.LF_POINTER(kwargs["type_data"])
        try:
            leaf_type = self._resolve_type(ptr.utype)
        except UnknownTPIType:
            print(f"unknown pointer type: 0x{ptr.utype:02x}")
            ptr_type = ptr.attr.ptrtype
            if ptr_type == c_pdb.CV_ptrtype_e.CV_PTR_64:
                leaf_type = c_pdb.uint64
            else:
                leaf_type = c_pdb.uint32

        return Pointer(self.pdb_cstruct, leaf_type)

    def _parse_lf_arglist(self, *args, **kwargs) -> cstruct:
        """Parser for the LF_ARGLIST leaf type.

        Returns:
            A `cstruct` object containing the pointer sizetype for the leaf type.
        """

        # TODO
        # lf_arglist = c_pdb.LF_ARGLIST(kwargs["type_data"])
        # Better to return as a pointer as this can be parsed in structures
        return self.pdb_cstruct.ptr

    def _parse_lf_fieldlist(self, *args, **kwargs) -> Iterable:
        """Parser for the LF_FIELDLIST leaf type.

        We use this fieldlist to parse the members within a struct. There's other types within a LF_FIELDLIST,
        but these aren't used to build the structs we form with cstruct.

        Args:
            length: The length of the TPI data.
            type_data: The `bytes` out of which the type is build.

        Returns:
            An `Iterable` list containing the different types associated with this fieldlist.
        """

        type_data = kwargs["type_data"]
        length = kwargs["length"]

        leaf_types = {
            c_pdb.LEAF_ENUM_e.LF_MEMBER: self._parse_lf_member,
            c_pdb.LEAF_ENUM_e.LF_MEMBER_ST: self._parse_lf_member,
            c_pdb.LEAF_ENUM_e.LF_STMEMBER: self._parse_lf_member,
            c_pdb.LEAF_ENUM_e.LF_STMEMBER_ST: self._parse_lf_member,
            c_pdb.LEAF_ENUM_e.LF_ENUMERATE: self._parse_lf_enumerate,
            c_pdb.LEAF_ENUM_e.LF_METHOD: self._parse_lf_method,
            c_pdb.LEAF_ENUM_e.LF_METHOD_ST: self._parse_lf_method,
            c_pdb.LEAF_ENUM_e.LF_ONEMETHOD: self._parse_lf_method,
            c_pdb.LEAF_ENUM_e.LF_ONEMETHOD_ST: self._parse_lf_method,
            c_pdb.LEAF_ENUM_e.LF_VFUNCTAB: self._parse_lf_vfunctab,
            c_pdb.LEAF_ENUM_e.LF_BCLASS: self._parse_lf_bclass,
            c_pdb.LEAF_ENUM_e.LF_BINTERFACE: self._parse_lf_bclass,
            c_pdb.LEAF_ENUM_e.LF_NESTTYPE: self._parse_lf_nesttype,
            c_pdb.LEAF_ENUM_e.LF_NESTTYPE_ST: self._parse_lf_nesttype,
            c_pdb.LEAF_ENUM_e.LF_NESTTYPEEX: self._parse_lf_nesttype,
            c_pdb.LEAF_ENUM_e.LF_NESTTYPEEX_ST: self._parse_lf_nesttype,
            c_pdb.LEAF_ENUM_e.LF_VBCLASS: self._parse_lf_vbclass,
            c_pdb.LEAF_ENUM_e.LF_IVBCLASS: self._parse_lf_vbclass,
            c_pdb.LEAF_ENUM_e.LF_INDEX: self._parse_lf_index,
            c_pdb.LEAF_ENUM_e.LF_INDEX_16t: self._parse_lf_index,
        }

        fieldlist = []

        while type_data.tell() < length:
            leaf_type = c_pdb.LEAF_ENUM_e(type_data)

            try:
                member = leaf_types[leaf_type](leaf_type=leaf_type, type_data=type_data)
                if leaf_type in [c_pdb.LEAF_ENUM_e.LF_MEMBER, c_pdb.LEAF_ENUM_e.LF_MEMBER_ST]:
                    # Only append members if these are of LF_MEMBER or LF_MEMBER_ST
                    fieldlist.append(member)
            except KeyError:
                # Leaf not supported yet
                # logging.debug(f"_parse_lf_fieldlist | leaf_type: {leaf_type} - member: {member}")
                pass

            # type_data is always 4 bytes aligned, align the data until we encounter another LF_MEMBER/LF_MEMBER_ST
            # leaf type
            type_data_pos = (type_data.tell() + 2) % 4
            if type_data_pos != 0:
                type_data.seek(4 - type_data_pos, os.SEEK_CUR)

        return fieldlist

    def _parse_lf_bitfield(self, *args, **kwargs) -> Tuple[CType, int, int]:
        """Parse any bitfields for the given type.

        Args:
            type_data: The TPI stream to parse.

        Returns:
            A `Tuple` containing the field type, number of bits, and the position within the type (offset).
        """

        type_data = kwargs["type_data"]

        type_index = c_pdb.uint32(type_data)
        field_type = self._resolve_type(type_index)

        number_of_bits = c_pdb.uint8(type_data) & 0xFF

        position = c_pdb.uint8(type_data)

        return (field_type, number_of_bits, position)

    def _parse_lf_array(self, *args, **kwargs) -> CType:
        """Parser for the LF_ARRAY leaf type.

        Args:
            type_data: The `bytes` out of which the type is build.

        Returns:
            The type of the array e.g. uint32[4], using `CType` to denote that it can be anything as the array in the
            C-language is not limited to a specific type except for Enum, Union, and Structure.
        """

        array = c_pdb.LF_ARRAY(kwargs["type_data"])
        field_type = self._resolve_type(array.elemtype)

        # if the type is an Enum, Union or Structure we don't need to specify the count
        if isinstance(field_type, Enum):
            return getattr(self.pdb_cstruct, field_type.name)

        elif isinstance(field_type, Union):
            return getattr(self.pdb_cstruct, field_type.name)

        elif isinstance(field_type, Structure):
            return getattr(self.pdb_cstruct, field_type.name)

        else:
            field_length = len(field_type)

        if field_length == 0:
            count = 0
        else:
            count = int(array.size / field_length)

        return field_type[count]

    def _parse_lf_structure(self, *args, **kwargs) -> Structure:
        """Parser for the LF_STRUCTURE leaf type.

        This function will build a `cstruct.Structure` object ouf of the type data given.
        This structure in turn can be used by the user to parse data from binary objects.

        Args:
            index: The index of the field, this is used if no name is associated with the struct.
            type_data: The `bytes` out of which the type is build.

        Returns:
            An instance of `cstruct.Structure`.
        """

        if kwargs["tpi_type"] in [c_pdb.LEAF_ENUM_e.LF_STRUCTURE, c_pdb.LEAF_ENUM_e.LF_CLASS]:
            lf_struct = c_pdb.LF_STRUCTURE(kwargs["type_data"])
        else:
            lf_struct = c_pdb.LF_STRUCTURE_16t(kwargs["type_data"])
        struct_name = get_name(data=kwargs["type_data"])

        # Some structs might not be named in a symbol file, these seem to have some kind of
        # naming convention when the symbol is coming from Microsoft at least.
        if struct_name in ["__unnamed", "<unnamed-tag>", "<anonymous-tag>"]:
            struct_name = f"unnamed_{kwargs['index']:04x}"

        if hasattr(self.pdb_cstruct, struct_name):
            # Retrieve the struct if we encountered this as a part of a forward declaration
            cstruct_struct = getattr(self.pdb_cstruct, struct_name)
        else:
            # Instantiate a new empty `Structure` if this is a new declaration
            cstruct_struct = Structure(self.pdb_cstruct, struct_name, [])

        if lf_struct.field != 0:
            # forward declaration?
            if not self.types[lf_struct.field]:
                return cstruct_struct

            for member in self.types[lf_struct.field]:
                try:
                    field_type = self._resolve_type(member_type=member.index)
                except UnknownTPIType:
                    """An UnknownType exception can occur when we're parsing a PDB file that wasn't originated by
                    Microsoft. These user compiled binaries may contain types that are not specified in the Microsoft
                    PDB format. Set the field type to the respective uint based on the index number when we encounter
                    such a type."""
                    # The 0x1000 range is reserved for 32-bit values
                    print(f"UnknownTPIType encountered: 0x{member.index:02x}")
                    if member.index & 0x1000:
                        field_type = c_pdb.uint32
                    else:
                        field_type = c_pdb.uint64

                if isinstance(field_type, tuple):
                    cstruct_struct.add_field(
                        name=member.name, type_=field_type[0], bits=field_type[1], offset=member.offset
                    )
                else:
                    cstruct_struct.add_field(name=member.name, type_=field_type, offset=member.offset)

        self.pdb_cstruct.addtype(name=struct_name, type_=cstruct_struct, replace=True)

        return cstruct_struct

    def _parse_lf_union(self, *args, **kwargs) -> Union:
        """Parser for the LF_UNION leaf type.

        Args:
            type_data: The `bytes` out of which the type is build.

        Returns:
            An instance of `cstruct.Union`.
        """

        lf_union = c_pdb.LF_UNION(kwargs["type_data"])
        if lf_union.property.fwdref and lf_union.field:
            field_type = self._resolve_type(member_type=lf_union.field)
            return field_type

        union_name = lf_union.name.decode()

        if union_name in ["__unnamed", "<unnamed-tag>", "<anonymous-tag>"]:
            union_name = f"unnamed_{kwargs['index']:04x}"

        if hasattr(self.pdb_cstruct, union_name):
            cstruct_union = getattr(self.pdb_cstruct, union_name)
        else:
            cstruct_union = Union(self.pdb_cstruct, union_name, [])

        if lf_union.field:
            for member in self.types[lf_union.field]:
                field_type = self._resolve_type(member_type=member.index)

                # Check if this member is a bitfield
                if isinstance(field_type, tuple):
                    cstruct_union.add_field(
                        name=member.name, type_=field_type[0], bits=field_type[1], offset=member.offset
                    )
                else:
                    cstruct_union.add_field(name=member.name, type_=field_type, offset=member.offset)

        self.pdb_cstruct.addtype(union_name, cstruct_union, replace=True)

        return cstruct_union

    def _parse_lf_enum(self, *args, **kwargs) -> Enum:
        """Parser for the LF_ENUM leaf type.

        Args:
            type_data: The `bytes` out of which the type is build.

        Returns:
            An instance of `cstruct.Enum`.
        """

        lf_enum = c_pdb.LF_ENUM(kwargs["type_data"])
        enum_name = lf_enum.name.decode()

        # Likely forward declaration, not supported by cstruct yet, return a pointer
        if not lf_enum.utype:
            import ipdb

            ipdb.set_trace()
            return self.pdb_cstruct.ptr

        field_type = self._resolve_type(member_type=lf_enum.utype)

        if hasattr(self.pdb_cstruct, enum_name):
            cstruct_enum = getattr(self.pdb_cstruct, enum_name)
        else:
            cstruct_enum = Enum(self.pdb_cstruct, enum_name, field_type, {})

        if isinstance(lf_enum.field, list):
            enum_fields = {}
            for member in self.types[lf_enum.field]:
                enum_fields[member.name] = member.value

            cstruct_enum = Enum(self.pdb_cstruct, enum_name, field_type, enum_fields)

        self.pdb_cstruct.addtype(enum_name, cstruct_enum, replace=True)

        return cstruct_enum

    def _parse_lf_mfunction(self, *args, **kwargs) -> Structure:
        """Parser for the LF_MFUNCTION and LF_MFUNCTION_16t leaf types.

        Returns:
            A `Structure` object for the leaf type.
        """

        if kwargs["tpi_type"] == c_pdb.LEAF_ENUM_e.LF_MFUNCTION:
            lf_function = c_pdb.LF_MFUNCTION(kwargs["type_data"])
        else:
            lf_function = c_pdb.LF_MFUNCTION_16t(kwargs["type_data"])

        return lf_function

    def _parse_lf_methodlist(self, *args, **kwargs) -> Structure:
        """Parser for the LF_METHOD and LF_METHOD_16t leaf types.

        Returns:
            A `Structure` object for the leaf type.
        """

        if kwargs["tpi_type"] == c_pdb.LEAF_ENUM_e.LF_METHODLIST:
            # TODO
            lf_methodlist = c_pdb.LF_METHOD(kwargs["type_data"])
        else:
            lf_methodlist = c_pdb.LF_METHOD_16t(kwargs["type_data"])
        return lf_methodlist

    def _parse_lf_vtshape(self, *args, **kwargs) -> CType:
        """Parser for the LF_VTABLE leaf type.

        Returns:
            A `CType` object for the leaf type.
        """

        # TODO
        try:
            lf_vtshape = c_pdb.LF_VTABLE(kwargs["type_data"])
        except EOFError:
            # Unsure how to parse this correctly
            return c_pdb.LF_VTABLE

        return lf_vtshape

    def _parse_lf_vftable(self, *args, **kwargs) -> CType:
        """Parser for the LF_VFTABLE leaf type.

        Returns:
            A `CType` object for the leaf type.
        """

        # TODO
        lf_vftable = c_pdb.LF_VFTABLE(kwargs["type_data"])

        return self._resolve_type(member_type=lf_vftable.type)

    def _parse_lf_enumerate(self, *args, **kwargs) -> Structure:
        """Parser for the LF_ENUMERATE leaf type.

        Returns:
            A `Structure` object for the leaf type.
        """

        type_data = kwargs["type_data"]
        offset = type_data.tell()
        lf_enumerate = c_pdb.LF_ENUMERATE(type_data)
        # Need to resolve the name seperately as there's a variable length
        type_data.seek(offset + c_pdb.CV_fldattr_t.size)
        lf_enumerate.name = get_name(data=type_data)

        return lf_enumerate

    def _parse_lf_member(self, *args, **kwargs) -> Structure:
        """Parser for the LF_MEMBER and LF_MEMBER_ST leaf types.

        Returns:
            A `Structure` object for the leaf type.
        """

        type_data = kwargs["type_data"]
        offset = type_data.tell()
        if kwargs["leaf_type"] in [c_pdb.LEAF_ENUM_e.LF_MEMBER, c_pdb.LEAF_ENUM_e.LF_MEMBER_ST]:
            lf_member = c_pdb.LF_MEMBER(type_data)
            # Need to resolve the name seperately as there's a variable length
            type_data.seek(offset + c_pdb.CV_fldattr_t.size + c_pdb.CV_typ_t.size)
            lf_member.name = get_name(data=type_data)
            return lf_member
        else:
            c_pdb.LF_STMEMBER(type_data)

    def _parse_lf_method(self, *args, **kwargs) -> Structure:
        """Parser for the LF_METHOD and LF_ONEMETHOD leaf types.

        Returns:
            A `Structure` object for the leaf type.
        """

        type_data = kwargs["type_data"]
        if kwargs["leaf_type"] == c_pdb.LEAF_ENUM_e.LF_METHOD:
            return c_pdb.LF_METHOD(type_data)

        header = c_pdb.LF_ONEMETHOD_HEADER(type_data)
        nember = c_pdb.LF_ONEMETHOD()

        nember.attr = header.attr
        nember.index = header.index
        nember.offset = type_data.tell()
        if header.attr.mprop in [c_pdb.CV_methodprop_e.CV_MTintro, c_pdb.CV_methodprop_e.CV_MTpureintro]:
            nember.offset = c_pdb.uint32(type_data)

        nember.name = c_pdb.char[None](type_data)

    def _parse_lf_vfunctab(self, *args, **kwargs) -> Structure:
        """Parser for the LF_VFUNCTAB leaf type.

        Returns:
            A `Structure` object for the leaf type.
        """
        return c_pdb.LF_VFUNCTAB(kwargs["type_data"])

    def _parse_lf_bclass(self, *args, **kwargs) -> Structure:
        """Parser for the LF_BCLASS leaf type.

        Returns:
            A `Structure` object for the leaf type.
        """
        return c_pdb.LF_BCLASS(kwargs["type_data"])

    def _parse_lf_nesttype(self, *args, **kwargs) -> Structure:
        """Parser for the LF_NESTTYPE leaf type.

        Returns:
            A `Structure` object for the leaf type.
        """
        return c_pdb.LF_NESTTYPE(kwargs["type_data"])

    def _parse_lf_vbclass(self, *args, **kwargs) -> Structure:
        """Parser for the LF_VBCLASS leaf type.

        Returns:
            A `Structure` object for the leaf type.
        """
        c_pdb.LF_VBCLASS(kwargs["type_data"])

    def _parse_lf_index(self, *args, **kwargs):
        """Parser for the LF_INDEX leaf type."""
        kwargs["type_data"].read(2)

    def _resolve_type(self, member_type: int) -> CType:
        """Function to resolve the type based on the index that is specified for the member type.

        Args:
            member_type: An integer that is used to denote the type used for the specific member.

        Returns:
            A `Ctype` instance that is associated with that specific member.

        Raises:
            UnknownType exception if the TPI type is not known.
        """

        if member_type in ARCH_POINTERS:
            # Just return a Pointer based on the architecture
            return Pointer(self.pdb_cstruct, self.pdb_cstruct.ptr)

        elif member_type in POINTER_TYPES:
            return Pointer(self.pdb_cstruct, POINTER_TYPES[member_type])

        elif member_type in self.types:
            return self.types[member_type]

        elif member_type in COMPILER_TYPES:
            return COMPILER_TYPES[member_type]

        raise UnknownTPIType(f"unknown type: 0x{member_type:02x}")
