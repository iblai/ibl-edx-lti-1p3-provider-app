class Lti1p3ProviderError(Exception):
    """Base app exception"""


class MissingSessionError(Lti1p3ProviderError):
    """Raised when user is missing lti access session information"""
