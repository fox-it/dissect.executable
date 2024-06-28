class Error(Exception):
    """Base exception for this module."""


class UnknownTPIType(Exception):
    """Unknown TPI type encountered."""


class TPIShortEntry(Exception):
    """Too short TPI entry."""
