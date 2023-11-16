import re


def _reformat_fetch_pub_key_error(err_text: str) -> str:
    """Return everything but response text

    In response to an LtiException error formatted like:
        f"Invalid response from {key_set_url}. Must be JSON: {resp.text}"
    """
    m = re.match("^(Invalid response from .*\. Must be JSON): .*", err_text)
    if m:
        return f"Error fetching platform public key. {m.groups()[0]}"

    return None


_REFORMATTERS = [
    _reformat_fetch_pub_key_error,
]


def reformat_error(err_text: str) -> str:
    """Reformat err_text to something more digestible

    Some exceptions contain a bunch of html which isn't reasonable to present
    to the user, so we reformat/remove unecessary information.
    """
    for reformatter in _REFORMATTERS:
        result = reformatter(err_text)
        if result:
            return result

    return err_text
