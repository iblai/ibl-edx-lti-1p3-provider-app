from tutor import hooks

hooks.Filters.ENV_PATCHES.add_items(
    [
        ("lms-env-features", """ENABLE_LTI_1P3_PROVIDER: true"""),
        (
            "openedx-lms-common-settings",
            """
if FEATURES.get("ENABLE_LTI_1P3_PROVIDER"):
    AUTHENTICATION_BACKENDS.append("lti_1p3_provider.auth.Lti1p3AuthenticationBackend")
""",
        ),
    ]
)
