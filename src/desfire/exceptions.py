class DESFireException(Exception):
    """Base exception for all DESFire exceptions."""

    pass


class DESFireCommunicationError(DESFireException):
    """Outgoing DESFire command received a non-OK reply.
    The exception message is human readable translation of the error code if available.
    The ``status_code`` carries the original status word error byte.
    """

    def __init__(self, msg, status_code):
        super().__init__(msg)
        self.status_code = status_code


class DESFireAuthException(DESFireException):
    """Exception raised when an authentication fails."""

    pass
