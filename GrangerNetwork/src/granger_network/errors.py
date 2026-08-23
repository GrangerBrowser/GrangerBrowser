class GrangerNetworkError(Exception):
    """Base error for the experimental network module."""


class AddressError(GrangerNetworkError):
    """Raised when a .granger name is malformed."""


class DescriptorError(GrangerNetworkError):
    """Raised when a signed service descriptor is invalid."""


class ResolutionError(GrangerNetworkError):
    """Raised when a local .granger mapping cannot be resolved."""


class TransportPolicyError(GrangerNetworkError):
    """Raised before a transport can escape the allowed private boundary."""


class ProtocolError(GrangerNetworkError):
    """Raised for malformed or unauthenticated protocol traffic."""


class IdentityVerificationError(ProtocolError):
    """Raised when the connected service does not own the expected identity."""


class UpstreamPolicyError(GrangerNetworkError):
    """Raised when a service host upstream is not a numeric loopback endpoint."""
