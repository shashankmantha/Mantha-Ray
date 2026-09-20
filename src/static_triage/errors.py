"""Project-specific exception types."""


class TriageError(Exception):
    """Base exception for expected scanner failures."""


class BoundaryError(TriageError):
    """Raised when a path violates the configured staging boundary."""


class LimitExceededError(TriageError):
    """Raised when a scan exceeds a configured resource limit."""