class Lti1p3ProviderError(Exception):
    """Base app exception"""


class MissingSessionError(Lti1p3ProviderError):
    """Raised when user is missing lti access session information"""


class DeepLinkingError(Lti1p3ProviderError):
    """Raised when there is an error with deep linking"""

    def __init__(self, title: str, message: str, status_code: int) -> None:
        self.title = title
        self.message = message
        self.status_code = status_code
        super().__init__(f"{title}: {message}")
