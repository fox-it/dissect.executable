import argparse
from typing import BinaryIO

# External imports
from dissect.cstruct import cstruct

# Local imports
from dissect.executable.pdb.helpers.c_pdb import PDB2_SIGNATURE, PDB7_SIGNATURE, c_pdb
from dissect.executable.pdb.helpers.dbi import DBI
from dissect.executable.pdb.helpers.pagestream import PageStream, pages
from dissect.executable.pdb.helpers.tpi import TPI


class PDBParser:
    """Base class for parsing PDB files.

    Args:
        fh: A file like object of a PDB file.
        pdb_cstruct: A `cstruct` object to use while parsing the type definitions of the PDB file.
    """

    def __init__(self, fh: BinaryIO, pdb_cstruct: cstruct = None):
        self.fh = fh
        # Define a new cstruct object for the types, use an existing one if given
        self.pdb_cstruct = cstruct() if not pdb_cstruct else pdb_cstruct
        self.streams = []
        self.dbi = None
        self.tpi = None
        self.types = {}
        self.machine = None

    def parse_streams(self):
        """Parse the streams within the PDB file.

        The root stream is parsed so a list of streams can be build which consist of the different stream types that
        are present within PDB files. See the `PageStream` class for a list with entry types.
        """

        self.root = self.root_def(self.root_stream)
        for stream_length in self.root.streamLengths:
            if stream_length.stream_size == 0xFFFFFFFF:
                stream_length.stream_size = 0
            pagecount = pages(size=stream_length.stream_size, page_size=self.header.page_size)
            self.streams.append(
                PageStream(
                    fh=self.fh,
                    pages=self.pagecount_sizetype[pagecount](self.root_stream),
                    size=stream_length.stream_size,
                    page_size=self.header.page_size,
                )
            )

        self._parse_dbi()
        self._parse_tpi()

    def _parse_dbi(self):
        """Parse the DBI stream within the PDB file.

        Some information that is present within the DBI stream is used throughout the rest of the PDB parsing.
        """

        self.dbi = DBI(streams=self.streams)
        self.machine = self.dbi.header.wMachine
        # Set the pointer size based on the machine architecture
        self.pdb_cstruct.ptr = self.pdb_cstruct.uint64 if self.machine == 0x8664 else self.pdb_cstruct.uint32

        # Parse the information within the DBI stream
        self.dbi.parse_info()

    def _parse_tpi(self):
        """Parse the TPI stream within the PDB file."""

        self.tpi = TPI(streams=self.streams, pdb_cstruct=self.pdb_cstruct)
        self.tpi.parse_types()

    @property
    def info(self) -> cstruct:
        """Return the PDB header that was parsed."""
        return self.header

    @property
    def symbols(self) -> dict:
        """Return the symbols `dict` of the PDB file."""
        return self.dbi.symbols

    @property
    def typedefs(self) -> cstruct:
        """Return the `cstruct` object containing the type definitions of the PDB file."""
        return self.tpi.typedefs()

    def parse_types(self, pdb_cstruct: cstruct = None) -> TPI:
        """Abstraction layer for parsing the types from the TPI stream.

        The parsed cstruct can be retrieved by using the `get_cstruct` function that is exposed from the `TPI` object.

        Args:
            pdb_cstruct: A `cstruct` definition to use, create a new one if not provided.

        Returns:
            A `TPI` object containing the types from the parsed PDB type definitions.
        """

        self.tpi.parse_types()
        return self.tpi


class PDB2(PDBParser):
    """Base class for parsing PDBv2 files.

    Args:
        fh: A file like object of a PDB file.
        header: The `cstruct` object for the PDB header, this is version specific.
        root: The `cstruct` object to use for parsing the root stream, this is version specific.
        pagecount_sizetype: The `cstruct` type to use for parsing the pages within the streams.
    """

    def __init__(self, fh: BinaryIO):
        super().__init__(fh=fh)
        self.header = c_pdb.PDB2_HEADER(self.fh)
        self.root_def = c_pdb.ROOT_STREAM_V2
        self.pagecount_sizetype = c_pdb.uint16

        # Retrieve the number of root pages
        root_pages = pages(size=self.header.root_size, page_size=self.header.page_size)

        # Parse the root stream
        root_pages = c_pdb.uint16[root_pages](self.fh)
        self.root_stream = PageStream(
            fh=self.fh, pages=root_pages, size=self.header.root_size, page_size=self.header.page_size
        )
        self.parse_streams()


class PDB7(PDBParser):
    """Base class for parsing PDBv7 files.

    Args:
        fh: A file like object of a PDB file.
        header: The `cstruct` object for the PDB header, this is version specific.
        root: The `cstruct` object to use for parsing the root stream, this is version specific.
        pagecount_sizetype: The `cstruct` type to use for parsing the pages within the streams.
    """

    def __init__(self, fh: BinaryIO):
        super().__init__(fh=fh)
        self.header = c_pdb.PDB7_HEADER(self.fh)
        self.root_def = c_pdb.ROOT_STREAM_V7
        self.pagecount_sizetype = c_pdb.uint32

        # Retrieve the number of root pages
        root_pages = pages(size=self.header.root_size, page_size=self.header.page_size)
        # Root pages in PDBv7 start from page_index * page_size
        offset = self.header.root_page_index * self.header.page_size
        self.fh.seek(offset)

        # Parse the root stream
        root_pages = c_pdb.uint32[root_pages](self.fh)
        self.root_stream = PageStream(
            fh=self.fh, pages=root_pages, size=self.header.root_size, page_size=self.header.page_size
        )
        self.parse_streams()


class PDB:
    """Base class for parsing PDB files.

    Depending on the PDB version the right PDB structures will be used to parse the PDB file.

    Args:
        pdb_file: The location of the PDB file to parse.
    """

    def __init__(self, pdb_file: str):
        self.fh = open(pdb_file, "rb")
        self._check_pdb_version()

    def _check_pdb_version(self):
        """Pick the right PDB parser depending on the version."""

        signature = self.fh.read(64)

        self.fh.seek(0)
        # Check the PDB signature to see with which version we're dealing
        if signature[: len(PDB7_SIGNATURE)] == PDB7_SIGNATURE:
            self.pdb = PDB7(fh=self.fh)
        elif signature[: len(PDB2_SIGNATURE)] == PDB2_SIGNATURE:
            self.pdb = PDB2(fh=self.fh)
        else:
            self.fh.close()
            raise NotImplementedError(f"Unsupported type observed: {signature}")

        self.header = self.pdb.header


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pdb", required=True, help="PDB file to parse.")
    parser.add_argument(
        "-i", "--info", required=False, action="store_true", help="Parse the PDB information within the DBI stream."
    )

    args = parser.parse_args()
    print(f"Parsing PDB: {args.pdb}")

    pdb_file = PDB(pdb_file=args.pdb)
    pdb = pdb_file.pdb

    if args.info:
        dbi = pdb.dbi
        pdb_cstruct = pdb.typedefs

        print(f"Found {len(dbi.module_info_list)} module info fields")
        print(f"Found {len(dbi.section_map_items)} section map items")
        print(f"Found {len(list(dbi.symbols))} symbols")
        print(f"{len(pdb_cstruct.typedefs)} type definitions found in pdb_cstruct")


if __name__ == "__main__":
    main()
