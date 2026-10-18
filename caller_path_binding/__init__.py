"""Pure byte-binding record helper (EVID-01 / DATA-01/02).

Binds caller-supplied bytes and a locator to an attempt, with size, digest and
declared collection metadata. It does not read the path or establish custody,
reader consumption, authentication or grading acceptance. The locator is never
treated as identity. No network, subprocess, clock reads or stored state.
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
