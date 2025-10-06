"""
========================
Content Libraries Models
========================

This module contains the models for new Content Libraries.

LTI 1.3 Models
==============

This is effectivly a re-implementation of the same concepts in the edx lti 1.1 provider
but now implemented for LTI 1.3.

Domain Model (Core concepts shown only - other meta data may exist):

┌─────────────────────────────────┐
│LtiGradedResource                │     ┌─────────────────┐
│                                 │     │LtiProfile       │
│- profile (FK)                   │     │                 │
│- course_key                     │     │- EdxUser (FK)   │
│- usage_key                      │────▶│- sub            │
│- resource_id (resource_link_id) │     │- iss            │
│- ags_lineitem (url)             │     │- client_id      │
│                                 │     └─────────────────┘
└─────────────────────────────────┘
                 │
                 │
                 ▼
      ┌─────────────────────┐
      │LtiTool              │
      │                     │
      │- platform_id (iss)  │
      │- client_id          │
      │- tool_key (FK)      │
      │                     │
      └─────────────────────┘
                 │
                 │
                 ▼
       ┌──────────────────┐
       │LtiToolKey        │
       │                  │
       │- name            │
       │- private_key     │
       │- public_key      │
       │- public_jwk      │
       │                  │
       └──────────────────┘
"""

from __future__ import annotations

import logging
import random
import string
import typing as t
from importlib import import_module

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction
from django.utils.translation import gettext_lazy as _
from opaque_keys import InvalidKeyError
from opaque_keys.edx.django.models import CourseKeyField, UsageKeyField
from opaque_keys.edx.keys import CourseKey, UsageKey
from organizations.models import Organization
from pylti1p3.contrib.django import DjangoDbToolConf, DjangoMessageLaunch
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey
from pylti1p3.grade import Grade

EDX_LTI_EMAIL_DOMAIN = "edx-lti-1p3.com"

log = logging.getLogger(__name__)

User = get_user_model()


def import_from_string(dotted_path: str) -> t.Callable:
    """
    Import an object (class, function, variable, etc.) from a dotted path string.
    Example: 'package.module.ClassName'
    """
    try:
        module_path, object_name = dotted_path.rsplit(".", 1)
    except ValueError:
        log.warning("Invalid module path: %s", dotted_path)
        raise ImportError(f"{dotted_path} doesn't look like a module path")

    module = import_module(module_path)
    try:
        return getattr(module, object_name)
    except AttributeError:
        log.warning("Module '%s' does not define a '%s'", module_path, object_name)
        raise ImportError(f"Module '{module_path}' does not define a '{object_name}'")


def validate_dl_content_filter_callback(dotted_path: str) -> None:
    """Raise ValidationError if dotted_path is not importable"""
    try:
        import_from_string(dotted_path)
    except ImportError as e:
        raise ValidationError(f"Invalid dl_content_filter_callback: {e}") from e


def create_edx_user(first_name: str, last_name: str) -> tuple[User, bool]:
    """Create an edX user with a random username/email and unusable passwordg"""
    username = generate_random_edx_username()
    # NOTE: Changed @{ContentLibrariesConfig.name}
    email = f"{username}@{EDX_LTI_EMAIL_DOMAIN}"
    user = User.objects.create(
        username=username, email=email, first_name=first_name, last_name=last_name
    )
    # LTI users can only auth throught LTI launches.
    user.set_unusable_password()
    user.save()
    log.info("Created new Edx LTI user: %s", user.username)
    return user


class LtiProfileManager(models.Manager):
    """
    Custom manager of LtiProfile mode.
    """

    def get_from_claims(self, *, iss, aud, sub, email=""):
        """
        Get the an instance from a LTI launch claims.
        """
        if email:
            return self.select_related("user__profile").get(
                platform_id=iss, client_id=aud, subject_id=sub
            )
        return self.select_related("user").get(
            platform_id=iss, client_id=aud, subject_id=sub
        )

    def get_or_create_from_claims(
        self, *, iss, aud, sub, email="", first_name="", last_name=""
    ):
        """
        Get or create an instance from a LTI launch claims.
        """
        try:
            # We don't need to lookup by email, only create by email so we have it
            return self.get_from_claims(iss=iss, aud=aud, sub=sub, email=email)
        except self.model.DoesNotExist:
            pass

        with transaction.atomic():
            try:
                user = create_edx_user(first_name, last_name)
            except IntegrityError:
                # In case we get a duplicate username - odds are very low so trying
                # once more should be sufficient
                log.warning("Failed to create LTI user due to IntegrityError; retrying")
                user = create_edx_user(first_name, last_name)
            return self.create(
                user=user,
                platform_id=iss,
                client_id=aud,
                subject_id=sub,
                email=email,
            )


class LtiProfile(models.Model):
    """
    Unless Anonymous, this should be a unique representation of the LTI subject
    (as per the client token ``sub`` identify claim) that initiated an LTI
    launch through the LTI 1.3 Provider.
    """

    objects = LtiProfileManager()

    user = models.OneToOneField(
        get_user_model(),
        null=True,
        on_delete=models.CASCADE,
        related_name="lti_1p3_provider_lti_profile",
        # Translators: 'Open edX' is a trademark, please keep this untranslated
        verbose_name=_("open edx user"),
    )

    platform_id = models.CharField(
        max_length=255,
        verbose_name=_("lti platform identifier"),
        help_text=_(
            "The LTI platform identifier (iss) to which this profile belongs to."
        ),
    )

    client_id = models.CharField(
        max_length=255,
        verbose_name=_("client identifier"),
        help_text=_("The LTI client identifier (aud) generated by the LTI platform."),
    )

    subject_id = models.CharField(
        max_length=255,
        verbose_name=_("subject identifier"),
        help_text=_(
            (
                "Identifies the entity that initiated the launch request, commonly a "
                "user (sub)."
            )
        ),
    )

    email = models.CharField(
        max_length=255,
        default="",
        verbose_name=_("email"),
        help_text=_("Email claim if provided"),
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ["platform_id", "client_id", "subject_id"]

    @property
    def subject_url(self):
        """
        An local URL that is known to uniquely identify this profile.

        We take advantage of the fact that platform id is required to be an URL
        and append paths with the reamaining keys to it.
        """
        return "/".join([self.platform_id.rstrip("/"), self.client_id, self.subject_id])

    def __str__(self):
        return self.subject_id


class LtiGradedResourceManager(models.Manager):
    """
    A custom manager for the graded resources model.
    """

    def upsert_from_ags_launch(
        self, user, course_key, usage_key, resource_endpoint, resource_link
    ):
        """
        Update or create a graded resource at AGS launch.
        """
        resource_id = resource_link["id"]
        resource_title = resource_link.get("title") or None
        lineitem = resource_endpoint["lineitem"]
        lti_profile = user.lti_1p3_provider_lti_profile
        # NOTE: Added resource_id to lookup as there could be > 1 resource link
        # pointing to the same course/usgae key for given user profile
        resource, _ = self.update_or_create(
            profile=lti_profile,
            course_key=course_key,
            usage_key=usage_key,
            resource_id=resource_id,
            defaults={
                "resource_title": resource_title,
                "ags_lineitem": lineitem,
            },
        )
        return resource

    def get_from_user_id(self, user_id, **kwds):
        """
        Retrieve a resource for a given user id holding an lti profile.
        """
        try:
            user = get_user_model().objects.get(pk=user_id)
        except get_user_model().DoesNotExist as exc:
            raise self.model.DoesNotExist("User specified was not found.") from exc
        profile = getattr(user, "lti_1p3_provider_lti_profile", None)
        if not profile:
            raise self.model.DoesNotExist("User does not have a LTI profile.")
        kwds["profile"] = profile
        return self.get(**kwds)


class LtiGradedResource(models.Model):
    """
    An LTI 1.3 resource launched through LTI with AGS enabled.

    Essentially, an instance of this model represents a successful LTI AGS
    launch.  This model links the profile that launched the resource with the
    resource itself, allowing identifcation of the link through its usage key
    string and user id.
    """

    objects = LtiGradedResourceManager()

    profile = models.ForeignKey(
        LtiProfile,
        on_delete=models.CASCADE,
        related_name="lti_1p3_provider_lti_resources",
        help_text=_(
            "The authorized LTI profile that launched the resource "
            "(identifies the user)."
        ),
    )

    course_key = CourseKeyField(
        max_length=255,
        help_text=_("The course key string the usage_key belongs to"),
    )

    usage_key = UsageKeyField(
        max_length=255,
        help_text=_("The usage key string of entity being served"),
    )

    resource_id = models.CharField(
        max_length=255,
        help_text=_(
            "The LTI platform unique identifier of this resource, also "
            'known as the "resource link id".'
        ),
    )

    resource_title = models.CharField(
        max_length=255,
        null=True,
        help_text=_("The LTI platform descriptive title for this resource."),
    )

    ags_lineitem = models.CharField(
        max_length=255,
        null=False,
        help_text=_(
            "If AGS was enabled during launch, this should hold the lineitem ID."
        ),
    )
    version_number = models.IntegerField(default=0)

    class Meta:
        unique_together = ["usage_key", "profile", "resource_id"]

    def update_score(self, weighted_earned, weighted_possible, timestamp):
        """
        Use LTI's score service to update the LTI platform's gradebook.

        This method synchronously send a request to the LTI platform to update
        the assignment score.
        """

        launch_data = {
            "iss": self.profile.platform_id,
            "aud": self.profile.client_id,
            "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint": {
                "lineitem": self.ags_lineitem,
                "scope": {
                    "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
                    "https://purl.imsglobal.org/spec/lti-ags/scope/score",
                },
            },
        }

        tool_config = DjangoDbToolConf()

        ags = (
            DjangoMessageLaunch(request=None, tool_config=tool_config)
            .set_auto_validation(enable=False)
            .set_jwt({"body": launch_data})
            .set_restored()
            .validate_registration()
            .get_ags()
        )

        if weighted_possible == 0:
            weighted_score = 0
        else:
            weighted_score = float(weighted_earned) / float(weighted_possible)

        log.debug(
            "Putting Grade - weighted_score: %s, timestamp: %s, sub: %s",
            weighted_score,
            timestamp.isoformat(),
            self.profile.subject_id,
        )
        ags.put_grade(
            Grade()
            .set_score_given(weighted_score)
            .set_score_maximum(1)
            .set_timestamp(timestamp.isoformat())
            .set_activity_progress("Submitted")
            .set_grading_progress("FullyGraded")
            .set_user_id(self.profile.subject_id)
        )

    def __str__(self):
        return str(self.usage_key)


def generate_random_edx_username():
    """
    Create a valid random edX user ID. An ID is at most 30 characters long, and
    can contain upper and lowercase letters and numbers.

    NOTE: Taken from lms.djangoapps.lti_provider.users
    """
    allowable_chars = string.ascii_letters + string.digits
    username = ""
    for _index in range(30):
        username = username + random.SystemRandom().choice(allowable_chars)
    return username


def validate_course_keys(course_keys: t.Any) -> None:
    """Validate a list of CourseKey strings"""
    if not isinstance(course_keys, list):
        raise ValidationError("Course keys must be a list")

    for key in course_keys:
        try:
            CourseKey.from_string(key)
        except InvalidKeyError:
            raise ValidationError(f"Invalid CourseKey: {key}")


def validate_allowed_orgs(orgs: t.Any) -> None:
    """Validate a list of Org strings"""
    if not isinstance(orgs, list):
        raise ValidationError("allowed_orgs must be a list")


def validate_usage_keys(usage_keys: t.Any) -> None:
    """Validate a list of UsageKey strings"""
    if not isinstance(usage_keys, list):
        raise ValidationError("Usage keys must be a list")

    for key in usage_keys:
        try:
            UsageKey.from_string(key)
        except InvalidKeyError:
            raise ValidationError(f"Invalid UsageKey: {key}")


def validate_course_block_filter(course_block_filter: t.Any) -> None:
    """Validate a course block filter"""
    if not isinstance(course_block_filter, dict):
        raise ValidationError(
            "Course block filter must be a dictionary of course keys and lists of edx block types"
        )
    validate_course_keys(list(course_block_filter.keys()))


def validate_org_block_filter(org_block_filter: t.Any) -> None:
    """Validate an org block filter"""
    if not isinstance(org_block_filter, dict):
        raise ValidationError(
            "Org block filter must be a dictionary of org short names and lists of edx block types"
        )


def validate_block_filter(block_filter: t.Any) -> None:
    """Validate a deep linking block filter"""
    if not isinstance(block_filter, list):
        raise ValidationError("Block filter must be a list of edx block types")


def block_filter_default() -> dict:
    """
    Default block filter.
    """
    return getattr(settings, "LTI_BLOCK_FILTER_DEFAULT", [])


class LaunchGate(models.Model):
    """Stores information about which xblocks a tool can access"""

    tool = models.OneToOneField(
        LtiTool,
        on_delete=models.CASCADE,
        help_text="The tool to gate",
        related_name="launch_gate",
    )
    allowed_keys = models.JSONField(
        default=list,
        help_text="Allows tool to access these specific UsageKeys",
        blank=True,
        validators=[validate_usage_keys],
    )
    allowed_courses = models.JSONField(
        default=list,
        help_text="Allows tool to access any content in these specific courses",
        blank=True,
        validators=[validate_course_keys],
    )
    allowed_orgs = models.JSONField(
        default=list,
        help_text="Allows tools to access any content in these orgs",
        blank=True,
        validators=[validate_allowed_orgs],
    )
    # Filters
    block_filter = models.JSONField(
        default=block_filter_default,
        help_text=(
            "Allow only these block types to be launched/deep linked with "
            "for anything not specified by the course_block_filter or org_block_filter. "
            "Must be a list of block types."
        ),
        blank=True,
        validators=[validate_block_filter],
    )
    course_block_filter = models.JSONField(
        default=dict,
        help_text=(
            "Allow only these block types to be launched in these courses. "
            "Valid format: {course_key: [block_types], ...}. These courses will only "
            "display these block types when deep linking."
        ),
        blank=True,
        validators=[validate_course_block_filter],
    )
    org_block_filter = models.JSONField(
        default=dict,
        help_text=(
            "Allow only these block types to be launched in these orgs. "
            "Valid format: {org_short_name: [block_types], ...}. These orgs will only "
            "display these block types when deep linking."
        ),
        blank=True,
        validators=[validate_org_block_filter],
    )
    dl_content_filter_callback = models.CharField(
        default="",
        blank=True,
        max_length=255,
        help_text="Optional callback to filter deep linking content",
        validators=[validate_dl_content_filter_callback],
    )

    def get_dl_content_filter_callback(self) -> t.Callable | None:
        """Return the dl_content_filter_callback if set, else None"""
        if self.dl_content_filter_callback:
            return import_from_string(self.dl_content_filter_callback)
        return None

    def can_access_key(self, usage_key: UsageKey) -> bool:
        """
        Determine if the tool can access the given usage key.

        This method performs a two-stage evaluation:
        1. **Access Control Check**: Verifies if the usage key is allowed based on
           allowed_keys, allowed_courses, or allowed_orgs (OR logic - any match grants access)
        2. **Block Type Filter Check**: Verifies if the usage key's block type is allowed
           based on block type filters (with specific precedence rules)

        If a block is in allowed_keys, it's unaffected by block filters.

        **Block Type Filter Precedence (evaluated in order):**

        1. **Course-specific filters** (`course_block_filter`): If the usage key's course
           has specific block type restrictions, only those block types are allowed.
           This takes highest precedence.

        2. **Organization-specific filters** (`org_block_filter`): If the usage key's
           organization has specific block type restrictions and no course-specific
           filter applies, only those block types are allowed.

        3. **Global filters** (`block_filter`): If no course or org-specific filters
           apply, the global block type filter is enforced.

        4. **No filters**: If no block type filters are configured, all block types
           are allowed (assuming access control passes).

        **Examples:**
        - If course_block_filter allows ['html', 'video'] for a course, only those
          block types are allowed for that course, regardless of org or global filters
        - If org_block_filter allows ['problem'] for an org and no course-specific
          filter exists, only 'problem' blocks are allowed for that org
        - If only block_filter is set to ['vertical'], only 'vertical' blocks are
          allowed globally (unless overridden by course/org filters)

        Args:
            usage_key: The UsageKey to check access for

        Returns:
            bool: True if the tool can access the usage key, False otherwise
        """
        # If it's an explicitly allowed key, we don't need to worry about block types
        if str(usage_key) in self.allowed_keys:
            return True

        is_usage_key_allowed = self._is_usage_key_allowed(usage_key)
        is_block_type_allowed = self._is_block_type_allowed(usage_key)
        return is_usage_key_allowed and is_block_type_allowed

    def _is_usage_key_allowed(self, usage_key: UsageKey) -> bool:
        """Return True if usage_key is allowed"""
        allowed_keys, allowed_courses, allowed_orgs = False, False, False
        if self.allowed_keys:
            allowed_keys = str(usage_key) in self.allowed_keys

        if self.allowed_courses:
            allowed_courses = str(usage_key.course_key) in self.allowed_courses

        if self.allowed_orgs:
            allowed_orgs = usage_key.course_key.org in self.allowed_orgs

        return allowed_keys or allowed_courses or allowed_orgs

    def _is_block_type_allowed(self, usage_key: UsageKey) -> bool:
        """Return True if usage key's block_type is allowed"""
        # If no filters are set, nothing is filtered out
        if not any(
            [
                bool(self.block_filter),
                bool(self.course_block_filter),
                bool(self.org_block_filter),
            ]
        ):
            return True

        block_type = usage_key.block_type
        course_key_str = str(usage_key.course_key)

        # if the block type is in courses block filter, we're not filtered out
        course_block_filter = self.course_block_filter.get(course_key_str, [])
        if course_block_filter:
            return False if block_type not in course_block_filter else True

        # if the block type is in orgs block filter, we're not filtered out
        org = usage_key.course_key.org
        org_block_filter = self.org_block_filter.get(org, [])
        if org_block_filter:
            return False if block_type not in org_block_filter else True

        # if we're in the global block filter, we're not filtered out
        if self.block_filter and block_type not in self.block_filter:
            return False

        return True


class LtiToolOrg(models.Model):
    """Association between a Tool and an Organization

    The short_name of an org is immutable, so we'll have to get our mutable version
    from the SiteConfiguration.site_values['platform_key']
    """

    tool = models.OneToOneField(
        LtiTool, on_delete=models.CASCADE, related_name="tool_org"
    )
    org = models.ForeignKey(Organization, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.tool.title} - {self.org}"


class LtiKeyOrg(models.Model):
    """Associates an LtiKey with an edx Organization"""

    key = models.OneToOneField(
        LtiToolKey, on_delete=models.CASCADE, related_name="key_org"
    )
    org = models.ForeignKey(Organization, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.key.name} - {self.org.short_name}"
