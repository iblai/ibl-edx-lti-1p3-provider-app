"""
========================
Content Libraries Models
========================

This module contains the models for new Content Libraries.

LTI 1.3 Models
==============

Content Libraries serves blockstore-based content through LTI 1.3 launches.
The interface supports resource link launches and grading services.  Two use
cases justify the current data model to support LTI launches.  They are:

1. Authentication and authorization.  This use case demands management of user
   lifecycle to authorize access to content and grade submission, and it
   introduces a model to own the authentication business logic related to LTI.

2. Grade and assignments.  When AGS is supported, content libraries store
   additional information concerning the launched resource so that, once the
   grading sub-system submits the score, it can retrieve them to propagate the
   score update into the LTI platform's grade book.

Relationship with LMS's ``lti_provider``` models
------------------------------------------------

The data model above is similar to the one provided by the current LTI 1.1
implementation for modulestore and courseware content.  But, Content Libraries
is orthogonal.  Its use-case is to offer standalone, embedded content from a
specific backend (blockstore).  As such, it decouples from LTI 1.1. and the
logic assume no relationship or impact across the two applications.  The same
reasoning applies to steps beyond the data model, such as at the XBlock
runtime, authentication, and score handling, etc.
"""

import logging
import uuid

from django.contrib.auth import get_user_model
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _
from lms.djangoapps.lti_provider.users import generate_random_edx_username
from opaque_keys.edx.django.models import CourseKeyField, UsageKeyField
from pylti1p3.contrib.django import DjangoDbToolConf, DjangoMessageLaunch
from pylti1p3.grade import Grade

EDX_LTI_EMAIL_DOMAIN = "edx-lti-1p3.com"

log = logging.getLogger(__name__)

User = get_user_model()


class LtiProfileManager(models.Manager):
    """
    Custom manager of LtiProfile mode.
    """

    def get_from_claims(self, *, iss, aud, sub):
        """
        Get the an instance from a LTI launch claims.
        """
        return self.get(platform_id=iss, client_id=aud, subject_id=sub)

    def get_or_create_from_claims(self, *, iss, aud, sub):
        """
        Get or create an instance from a LTI launch claims.
        """
        try:
            return self.get_from_claims(iss=iss, aud=aud, sub=sub)
        except self.model.DoesNotExist:
            # User will be created on ``save()``.
            return self.create(platform_id=iss, client_id=aud, subject_id=sub)


class LtiProfile(models.Model):
    """
    Content Libraries LTI's profile for Open edX users.

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

    def save(self, *args, **kwds):
        """
        Get or create an edx user on save.
        """
        if not self.user:
            username = generate_random_edx_username()
            # NOTE: Changed @{ContentLibrariesConfig.name}
            email = f"{username}@{EDX_LTI_EMAIL_DOMAIN}"
            with transaction.atomic():
                if self.user is None:
                    self.user, created = User.objects.get_or_create(
                        username=username, defaults={"email": email}
                    )
                    if created:
                        # LTI users can only auth throught LTI launches.
                        self.user.set_unusable_password()
                    self.user.save()

        super().save(*args, **kwds)

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
        resource, _ = self.update_or_create(
            profile=lti_profile,
            course_key=course_key,
            usage_key=usage_key,
            defaults={
                "resource_title": resource_title,
                "resource_id": resource_id,
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
        unique_together = ["usage_key", "profile"]

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
