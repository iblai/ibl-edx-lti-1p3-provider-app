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

from django.contrib.auth import get_user_model
from django.db import IntegrityError, models, transaction
from django.utils.translation import gettext_lazy as _
from opaque_keys.edx.django.models import CourseKeyField, UsageKeyField
from opaque_keys.edx.keys import UsageKey
from organizations.models import Organization
from pylti1p3.contrib.django import DjangoDbToolConf, DjangoMessageLaunch
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey
from pylti1p3.grade import Grade

EDX_LTI_EMAIL_DOMAIN = "edx-lti-1p3.com"

log = logging.getLogger(__name__)

User = get_user_model()


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
    )
    allowed_courses = models.JSONField(
        default=list,
        help_text="Allows tool to access these specific CourseKey's",
        blank=True,
    )
    allowed_orgs = models.JSONField(
        default=list,
        help_text="Allows tools to access any content in these orgs",
        blank=True,
    )

    def can_access_key(self, usage_key: UsageKey) -> bool:
        """Return True if tool can access usage_key

        This is evaluated as an OR of allowed_keys, allowed_courses, allowed_orgs
        """
        allowed_keys, allowed_courses, allowed_orgs = False, False, False
        if self.allowed_keys:
            allowed_keys = str(usage_key) in self.allowed_keys

        if self.allowed_courses:
            allowed_courses = str(usage_key.course_key) in self.allowed_courses

        if self.allowed_orgs:
            allowed_orgs = usage_key.course_key.org in self.allowed_orgs

        return allowed_keys or allowed_courses or allowed_orgs


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
