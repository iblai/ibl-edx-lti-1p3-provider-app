# LTI 1.3 Provider

## Unreleased

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
