"""Dynamic caller-path binding and custody (EVID-01 / DATA-01/02).

Binds the bytes actually read from a caller-selected path (not just the
path string) to an attempt, with size, digest and collection metadata.
Pure and fail-closed: the locator is never treated as identity.  No
network, no subprocess, no clock reads, no stored module state.
"""

from .binding import (
    CallerPathBindingError,
    CallerPathBinding,
    bind_caller_path,
    BINDING_VERSION,
)

__all__ = [
    "CallerPathBindingError",
    "CallerPathBinding",
    "bind_caller_path",
    "BINDING_VERSION",
]
