# LTI 1.3 Provider

## Unreleased

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
