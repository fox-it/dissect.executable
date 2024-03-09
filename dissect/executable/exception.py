class Error(Exception):
    """Base exception for this module."""


class InvalidSignatureError(Error):
    """Exception that occurs if the magic in the header does not match."""


class InvalidPE(Error):
    """Exception that occurs if the PE signature does not match."""


class InvalidVA(Error):
    """Exception that occurs when a virtual address is not found within the PE sections."""


class InvalidAddress(Error):
    """Exception that occurs when a raw address is not found within the PE file when translating from a virtual
    address."""


class InvalidArchitecture(Error):
    """Exception that occurs when an invalid value is encountered for the PE architecture types."""


class BuildSectionException(Error):
    """Exception that occurs when the section to be build contains an error."""


class ResourceException(Error):
    """Exception that occurs when an error is thrown parsing the resources."""
