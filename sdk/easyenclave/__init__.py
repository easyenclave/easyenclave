"""EasyEnclave SDK - Client library for the EasyEnclave discovery service."""

from .client import (
    ControlPlaneNotVerifiedError,
    EasyEnclaveClient,
    EasyEnclaveError,
    ServiceClient,
    ServiceNotFoundError,
    VerificationError,
)
from .verify import (
    TDXMeasurements,
    VerificationResult,
    parse_tdx_quote,
    verify_quote_local,
    verify_quote_with_intel_ta,
)

__all__ = [
    # Client classes
    "EasyEnclaveClient",
    "ServiceClient",
    # Exceptions
    "EasyEnclaveError",
    "ServiceNotFoundError",
    "VerificationError",
    "ControlPlaneNotVerifiedError",
    # Verification
    "TDXMeasurements",
    "VerificationResult",
    "parse_tdx_quote",
    "verify_quote_local",
    "verify_quote_with_intel_ta",
]
__version__ = "0.1.0"
