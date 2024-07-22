class Error(Exception):
    """Base exception for this module."""


class InvalidSignatureError(Error):
    """Exception that occurs if the magic in the header does not match."""

class InvalidDataType(Error):
    """Exception that occurs if the datatype of a cell in an MSI table is not a valid type."""
    pass

class InvalidStringData(Error):
    """Exception that occurs if the information on strings from an MSI tables is incorrect."""
    pass

class InvalidTable(Error):
    """Exception that occurs if an MSI table is not restored correctly."""
    pass
