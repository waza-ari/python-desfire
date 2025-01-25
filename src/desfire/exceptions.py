class DESFireException(Exception):
    """Base exception for all DESFire exceptions."""

    pass


class DESFireAuthException(DESFireException):
    """Exception raised when an authentication fails."""

    pass
