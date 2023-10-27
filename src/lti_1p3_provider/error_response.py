from typing import Any

from django.http import HttpResponse
from django.template import loader


class ErrorResponse(HttpResponse):
    def __init__(
        self,
        request,
        context=None,
        content_type=None,
        status=None,
        using=None,
    ):
        content = loader.render_to_string(
            "lti_1p3_provider/erorr.html", context, request, using=using
        )
        return super().__init__(content, content_type, status)
