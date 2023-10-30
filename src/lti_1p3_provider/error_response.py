from __future__ import annotations

from typing import Any
from urllib import parse

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render


class LTIErrorRedirect(HttpResponseRedirect):
    """Redirects user to the LTI return_url with error message and logs set in qs"""

    def __init__(
        self,
        return_url: str,
        title: str,
        errormsg: str,
        errorlog: str = "",
        *args: Any,
        **kwargs: Any,
    ) -> None:
        qps = self._get_lti_query_params(title, errormsg, errorlog)
        return_url = self._add_lti_error_to_qs(return_url, qps)
        super().__init__(return_url, *args, **kwargs)

    def _get_lti_query_params(
        self, title: str, errormsg: str, errorlog: str = ""
    ) -> str:
        """Build and return the query params for the lti query string"""
        query_string = {"lti_errormsg": f"{title}: {errormsg}"}
        if errorlog:
            query_string["lti_errolog"] = errorlog
        return query_string

    def _add_lti_error_to_qs(return_url: str, lti_query_params: dict[str, str]) -> str:
        """Return lti return_url with additional lti query params set"""
        parts = parse.urlparse(return_url)
        query = parse.parse_qs(parts.query)
        query.update(lti_query_params)
        query_str = parse.urlencode(query)
        parts = parts._replace(query=query_str)
        return parse.urlunparse(parts)


def get_lti_error_response(
    request,
    launch_data: dict,
    title: str = "Invalid LTI Tool Launch",
    errormsg: str = "Please contact your technical support for additional assistance",
    errorlog="",
    status: int | None = None,
) -> HttpResponse:
    """Return redirect to lti return url if present, else return nice error response

    Params:
        request (HttpRequest): Django Request Object
        launch_data (dict): LTI Launch Data from JWT
        title (str): Title of error
        errormsg (str): Error message intended to be shown to the user
        errorlog (str): Error messages intended for logging on the LTI Consumer
        status (int): Optional status for when return_url not present in launch_data

    https://www.imsglobal.org/spec/lti/v1p3/#launch-presentation-claim
    """
    presentation = _get_launch_presentation(launch_data)
    return_url = presentation.get("return_url")
    if return_url:
        return LTIErrorRedirect(return_url, title, errormsg, errorlog)

    return render_edx_error(request, title, errormsg, status=status)


def _get_launch_presentation(launch_data: dict) -> dict:
    """Return launch presentation if populated"""
    return launch_data.get(
        "https://purl.imsglobal.org/spec/lti/claim/launch_presentation", {}
    )


def render_edx_error(
    request: HttpRequest, title: str, error: str, status: int
) -> HttpResponse:
    """Return HttpResponse w/ nicer edx style template"""
    context = {"title": title, "error": error, "disable_header": True}
    return render(request, "lti_1p3_provider/error.html", context, status=status)
