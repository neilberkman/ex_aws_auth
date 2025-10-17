## [1.2.0] - 2025-01-17

### Added

- `AWSAuth.Credentials` struct for cleaner credential management
  - `from_env/0` to load credentials from environment variables
  - `from_map/1` to create from maps or keyword lists
- Credential struct overloads for simpler signing
  - `sign_url(credentials, method, url, service, opts)`
  - `sign_authorization_header(credentials, method, url, service, headers, payload, opts)`
- `return_format` option for flexible header formats
  - `:list` (default) - Returns list of tuples `[{header, value}]`
  - `:map` - Returns map `%{header => value}`
  - `:req` - Returns Req-compatible format `%{header => [value]}`
- `AWSAuth.Req` plugin module for seamless Req integration
  - Automatically signs Req requests with AWS Signature V4
  - Handles header format conversion transparently
  - Supports all credential types (long-term, STS temp credentials)
- Optional Req and Jason dependencies for plugin support

### Changed

- Timestamp parameter now optional in credential struct APIs (defaults to current time)
- All new APIs maintain 100% backward compatibility with existing function signatures

---

## [1.1.0] - 2025-01-17

### Added

- Session token support for temporary AWS credentials (STS AssumeRole)
  - New optional `session_token` parameter for `sign_url/10` and `sign_authorization_header/10`
  - Automatically adds `X-Amz-Security-Token` header for authorization header signing
  - Automatically adds `X-Amz-Security-Token` query parameter for URL signing
- Header filtering to remove unsignable headers (`x-amzn-trace-id`)
  - Prevents AWS infrastructure trace headers from breaking signatures
- Header value normalization
  - Collapses multiple consecutive spaces to single space per AWS Sig V4 spec
- Query parameter validation
  - Rejects list keys/values with clear error messages

### Changed

- Headers are now filtered and normalized before signing in all signing methods
- Query parameters are validated before canonical request generation

---

## [1.0.1] - 2025-01-16

### Changed

- Updated to Elixir 1.19.0 and OTP 28.1 in CI/CD pipeline
- Updated .tool-versions to Elixir 1.19.0/OTP 28.1

---

## [1.0.0] - 2025-01-15

### Initial Release

This is a fork of the original `aws_auth` package by Bryan Joseph, incorporating OTP 27 compatibility fixes from Rodrigo Zampieri Castilho's fork. Published as `ex_aws_auth` to make this maintained version available on Hex.

### Changed

- Updated minimum Elixir requirement to ~> 1.14
- Modernized all dependencies (ex_doc ~> 0.34, credo ~> 1.7, excoveralls ~> 0.18)
- Migrated from deprecated `Mix.Config` to `import Config`

### Added

- Quokka ~> 2.11 formatter plugin for code quality
- dialyxir ~> 1.4 for static analysis
- Comprehensive .formatter.exs configuration

---

## Historical Changelog (from original `aws_auth` package)

## [0.6.1]

### Fixed

- Correctly handle NaiveDateTimes with ms precision (thanks to [@radar](https://github.com/radar))

## [0.6.0]

### Changed

- Requires Elixir 1.3 or higher

### Fixed

- Removed timex dependency and using Elixir's built in datetime functions (thanks to [@radar](https://github.com/radar))

## [0.5.1]

### Fixed

- Use Timex.DateTime.now, rather than Timex.DateTime.today (thanks to [@radar](https://github.com/radar))

## [0.5.0]

### Fixed

- `x-amz-date` using Date instead of DateTime (thanks to [@radar](https://github.com/radar))

### Changed

- Dependency updates (thanks to [@radar](https://github.com/radar))

## [0.4.0]

### Fixed

- Signing works for more than just S3 from @kenta-aktsk

### Changed

- headers params for `sign_url` and `sign_authorization_header` now expects a map instead of a Dict
