class RunbookOSError(Exception):
    """Base error suitable for presenting to a CLI user."""


class ConfigurationError(RunbookOSError):
    pass


class PolicyDenied(RunbookOSError):
    pass


class ExecutionUnknown(RunbookOSError):
    """The transport failed after dispatch; the remote outcome is not knowable."""


class ApprovalError(RunbookOSError):
    pass
