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


class DlBlockFilterError(Lti1p3ProviderError):
    """Raised when there is an error with the deep linking block filter

    Args:
        developer_message: A message for the developer to help debug the issue
        user_message: A message for the user to explain the issue

    If no user_message is provided, a generic error will be returned.
    """

    def __init__(self, dev_message: str = "", user_message: str = "") -> None:
        self.user_message = user_message
        self.dev_message = dev_message or user_message
