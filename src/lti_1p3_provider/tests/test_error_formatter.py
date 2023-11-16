from lti_1p3_provider.error_formatter import reformat_error


def test_reformatting_pub_key_error():
    """Reformats invalid response from jwks endpoint error"""
    err_text = (
        "Invalid response from https://some.website.com/thing/json-endpoint. "
        "Must be JSON: <html><head></head><body>some text</body></html>."
    )

    expected = (
        "Error fetching platform public key. Invalid response from "
        "https://some.website.com/thing/json-endpoint. Must be JSON"
    )

    assert reformat_error(err_text) == expected


def test_no_formatting_applied_if_no_matches():
    """If no matching functions, returns the original text"""
    err_text = "Please don't reformat me"

    assert reformat_error(err_text) == err_text
