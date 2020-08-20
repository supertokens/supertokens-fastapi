# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2020-08-09
### Added
- Support for refresh tokens in Auth0 handler
- Adds `get_cors_allowed_headers` function for easier CORS
- Compatibility with CDI 2.2

## Fixes
- Incorrectly deleting session items from session data for Auth0 handler