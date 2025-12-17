# LTI 1.3 Provider

## Unreleased

## 2.5.3
### Changed
- [#54](https://github.com/iblai/ibl-edx-lti-1p3-provider-app/issues/54): Remove `custom` claim from Deep Linking ltiResourceLink content items if empty
  - Fixes Moodle (it fails if the custom claim is an empty dict)

## 2.5.2
### Changed
- [#52](https://github.com/iblai/ibl-edx-lti-1p3-provider-app/issues/52): Store the lti-1p3-launch-id from pylti1p3 in the users session

## 2.5.1
### Changed
- [#50](https://github.com/iblai/ibl-edx-lti-1p3-provider-app/issues/50): Remove the lti data claim during deep linking if not originally sent
  - pylti1p3 sets the value to `null` if it's not sent instead of not including it at all, which can cause downstream issues
  - fixes logging when clearing deep linking session so it logs session id instead of values that didn't exist in dict
  - changes default LTI deep linking roles to the following by default:
    - "http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator"
    - "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator"
    - "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor"
    - "http://purl.imsglobal.org/vocab/lis/v2/membership#Administrator"
    - "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"
    - "http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper"

## 2.5.0
### Added
- [#47](https://github.com/iblai/ibl-edx-lti-1p3-provider-app/issues/47): Add filter hook to register custom filtering functions per `LaunchGate` 

## 2.4.1
### Changed
- [#45](https://github.com/iblai/ibl-edx-lti-1p3-provider-app/issues/45): Further validate the `target_link_uri` to ensure:
  - It's domain is our domain (so we don't send the user outside our platform)
  - It's specifically out `lti-display` endpoint - that's the only place we can go
  - Return a more specific error if someone sets it to our deep-linking/lti-launch endpoints (common mistakes)

## 2.4.0
### Added
- [#44](https://github.com/iblai/ibl-edx-lti-1p3-provider-app/issues/44): Adds support for Deep Linking.`ltiResourceLink` is the only supported resource type.
  - Adds new fields to `LaunchGate` model: `block_filter`, `course_block_filter`, `org_block_filter`
    - These further control what content can be DeepLinked with and launched based on the block types in each filter category where `block_filter` is the final catch-all if defined.
  - Adds new endpoints:
    - /lti/1p3/deep-linking/launch/ - for deep link launches
    - /lti/1p3/deep-linking/select-content/<slug:token>/ - for selecting deep link content to return
  - Fixes `test_grades.py` to work with sumac

## 2.3.7
### Fixed
- [#40](https://github.com/iblai/ibl-edx-lti-1p3-provider-app/issues/40): Fix session cookie error pattern matching to properly catch missing lti1p3-session-id cookie errors
    - Implements regex pattern matching for "Missing .* cookie session-id" error messages from pylti1p3
    - Updates error message to be user-friendly about Safari and private/incognito windows

## 2.3.6
### Changed
- [#34](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/34): Don't allow LtiKey's to be deleted if they are still referenced by an LTITool

## 2.3.5
### Changed
- [#37](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/37): Handle email claim being `null`

## 2.3.4
### Changed
- [#35](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/35): Show user friendly missing session-cookie specific error when lti1p3-session-id is missing

## 2.3.3
### Changed
- [#32](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/32): Update `UserProfile.name` with `{given_name} {family_name}` if present in claims

## 2.3.2
### Changed
- [#30](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/30): Store `given_name` and `family_name` claims on `User` object if present
    - Stored on `User.first_name` and `User.last_name`, respectively

## 2.3.1
### Changed
- [#28](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/28): Stores JWT email claim in `UserProfile.meta` and `LtiProfile.email` if present
    - Adds `email` field to `LtiProfile`
    - Creates `UserProfile` if it doesn't exist

## 2.3.0
### Adds
- [#25](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/25): Adds `allowed_courses` to `LaunchGate`
- [#21](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/21): Adds API to manage `LtiToolKey`'s at a tenant level
- [#22](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/22): Adds API to manage `LtiTool`'s at a tenant level

## 2.2.0
### Added
- [#15](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/15): Adds a `LtiToolOrg` model to associate Tools with an Organization (multi-tenant)

### Fixed
- [#15](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/15): Log statment error when launching with no launch gate


## 2.1.0
### Added
- [#16](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/16): Adds a `LaunchGate` model where we can define whether a tool can launch a specific `UsageKey`
    - If no `LaunchGate` is attached to the tool, there are no restrictions
    - If a `LaunchGate` is attached to the tool, the tool can only launch if the `UsageKey` is explicitly defined or the `UsageKey` belongs to a white listed org

## v2.0.2 - 2023-11-16
### Changed
- [#12](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/12): Return actionable error messages to the user.

## v2.0.1 - 2023-11-04
### Changed
- [#10](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/10): If `LTI_1P3_PROVIDER_ACCESS_LENGTH_SEC` is `None` (default), allow access as long as logged in.

## v2.0.0 - 2023-11-01
### Changed
- 💥 [#1](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/1): Use static `redirect_uri` (`/lti/1p3/launch/`); 302 redirect to `target_link_uri` after POST to `redirect_uri` (**Breaking Change**)
- [#6](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/6): Show nicer error page if user hits browser Back button after launch

## v1.0.1
### Fixed
- [#4](https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app/issues/4): Pull in `generate_random_edx_username` definition from `lms.djangoapps.lti_provider.users`

## v1.0.0 - Initial Release
