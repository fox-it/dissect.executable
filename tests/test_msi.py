import pytest
from dissect.executable import MSI
from dissect.executable.exception import InvalidTable
from dissect.ole.exceptions import InvalidFileError, NotFoundError
from io import BytesIO

def test_msi_invalid_signature():
    with pytest.raises(InvalidFileError):
        MSI(BytesIO(b"error" + b"\x00" * 0x200))

def test_msi_valid_signature():
    with open("./data/test_msi.msi", "rb") as fh:
        MSI(fh)

def test_msi_listdir():
    known_directory_entries = [
        '_Media',
        '__Columns',
        '__Tables',
        '_Feature',
        '_Registry',
        '_Property',
        'required.cab',
        '_Directory',
        '_Component',
        '__StringData',
        '__StringPool',
        '__Validation',
        '_AdminUISequence',
        '_FeatureComponents',
        '_InstallUISequence',
        '_AdminExecuteSequence',
        '_AdvtExecuteSequence',
        '_MsiPatchCertificate',
        '_InstallExecuteSequence',
        '_MsiDigitalCertificate',
        '\x05DigitalSignature',
        '\x05SummaryInformation',
        'MsiDigitalCertificate.CertificateForPatching'
    ]
    with open("./data/test_msi.msi", "rb") as fh:
        msi = MSI(fh)
        assert known_directory_entries == [dir_entry for dir_entry in msi.listdir()]

def test_invalid_directory_entry():
    with open("./data/test_msi.msi", "rb") as fh:
        msi = MSI(fh)
        assert isinstance(msi.get("invalid name"), NotFoundError) # OLE.get doesn't raise the error, but returns it

def test_valid_directory_entry():
    with open("./data/test_msi.msi", "rb") as fh:
        msi = MSI(fh)
        dir_entry = msi.get("_Registry")
        assert dir_entry != None

def test_msi_load_tables():
    known_table_names = [
        "_Validation",
        "AdminExecuteSequence",
        "AdminUISequence",
        "AdvtExecuteSequence",
        "Component",
        "Directory",
        "Feature",
        "FeatureComponents",
        "File",
        "InstallExecuteSequence",
        "InstallUISequence",
        "Media",
        "Property",
        "MsiDigitalCertificate",
        "MsiPatchCertificate",
        "Registry"
    ]
    with open("./data/test_msi.msi", "rb") as fh:
        msi = MSI(fh)
        assert known_table_names == [table.name for table in msi.get_tables()]

def test_invalid_table():
    with open("./data/test_msi.msi", "rb") as fh:
        msi = MSI(fh)
        with pytest.raises(InvalidTable):
            msi.get_table("invalid name")

def test_msi_rows():
    with open("./data/test_msi.msi", "rb") as fh:
        msi = MSI(fh)
        t = msi.get_table("Registry")
        for i, row in enumerate(t.rows()):
            continue
        assert i == 0
        assert t.n_rows == i + 1
        assert row._table_name == "Registry"
        assert row._cells['Registry'] == b'NonEmptyComponent'
        assert row._cells['Key'] == b'SOFTWARE\\DropboxUpdate\\Update'

def test_msi_columns():
    with open("./data/test_msi.msi", "rb") as fh:
        msi = MSI(fh)
        t = msi.get_table("Registry")
        for i, col in enumerate(t.columns):
            continue
        assert i == 5
        assert t.n_cols == i + 1
        assert t.columns[i].name == b'Component_'
        assert t.columns[i].cells[0] == b'MainComponent'

def test_invalid_dump_stream():
    with open("./data/test_msi.msi", "rb") as fh:
        msi = MSI(fh)
        with pytest.raises(NotFoundError):
            msi.dump_stream("invalid name")
