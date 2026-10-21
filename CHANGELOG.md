## [1.5.0] - 2026-10-21

### Fixed

- S3-family requests (`s3`, `s3-outposts`, `s3-object-lambda`, `s3express`) sign the wire path verbatim and presign with `UNSIGNED-PAYLOAD` (with `auth_scheme: :s3express_session` opt-in for S3 Express `CreateSession` credentials using `x-amz-s3session-token` / `X-Amz-S3session-Token`); previously the path was percent-encoded a second time, so any key with a space, `+`, `(`, `=`, `@` or non-ASCII byte produced `SignatureDoesNotMatch` under default options.
- Canonical headers are sorted by name, not by `name:value`.
- Header names are case-folded before generated headers are added; `Host` no longer produces `SignedHeaders=host;host`.
- Host header includes a non-default port and brackets IPv6 literals; presigned URLs for LocalStack/MinIO on a port now verify.
- Non-S3 paths are normalized (`remove_dot_segments`, empty segments collapsed) before encoding.
- Header values collapse all whitespace, not only spaces.
- `sign_url/5` honors `:unsigned_headers`.
- Unsigned headers (now defaulting to botocore's full `SIGNED_HEADERS_BLACKLIST`, including `user-agent`, `expect`, hop-by-hop headers, and `x-amzn-trace-id`) are excluded from signing but kept in the returned headers and in Req requests.
- Req plugin: `host` is regenerated on re-sign and across origin changes; streaming bodies sign as `UNSIGNED-PAYLOAD`; multi-valued headers are comma-joined in order (preserving repeated values) instead of truncated; untrusted cross-origin redirects are not re-signed and unconditionally strip credential headers and `host`.
- Service detection uses botocore's endpoint-prefix, endpoint-rules, and partition tables (96 unique prefixes, including China endpoint aliases), handles S3 FIPS/dual-stack/access-point/outposts/express endpoint variants, strips `-fips` per label, supports `.api.aws` and uppercase hostnames, and preserves mixed-case signing names (`IoTSecuredTunneling`, `IngestionService`).

### Changed

- Region precedence is explicit option, then URL, then `credentials.region`, then `us-east-1`. Previously `credentials.region` beat the URL.
- Service names are preserved in their given case rather than lowercased so mixed-case AWS signing names (`IoTSecuredTunneling`, `IngestionService`) sign with a valid credential scope.
- Returned header names are lowercase.
- `credentials` structs redact the secret key and session token in `inspect/1`.
- `attach/2` rejects unknown options.

---

## [1.4.2] - 2026-09-03

### Fixed

- Run Req signing after its built-in URL, query, body encoding, and compression steps.
- Replace prior SigV4 headers when Req re-signs a retried request.
- Encode canonical URI paths and query parameters according to AWS SigV4 rules.
- Preserve and sort duplicate query parameters when signing requests.
- Detect virtual-hosted, dotted-bucket, dual-stack, China, and legacy regional S3 endpoints.
- Validate presigned URL expirations while continuing to accept integer strings from configuration.

---

## [1.4.1] - 2026-06-15

### Added

- Request-side helpers that complete the event-stream support added in 1.4.0:
  - `AWSAuth.EventStream.encode_string_header/2` — type-7 string header encoder
    (for application headers like `:content-type`/`:event-type`/`:message-type`).
  - `:streaming_events` payload option for `sign_authorization_header/5`, which
    seeds an event-stream request with
    `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-EVENTS`.

---

## [1.4.0] - 2026-06-15

### Added

- **Event stream signing for bidirectional streaming APIs** (`AWSAuth.EventStream`)
  - `sign_message/6` signs an event and returns a wire-ready event stream frame
    (prelude + CRCs + `:date`/`:chunk-signature` headers + payload), plus the
    signature to chain into the next event
  - `sign_event/7` low-level signer matching the canonical
    `AWS4-HMAC-SHA256-PAYLOAD` algorithm
  - Helpers for encoding event stream headers and framing messages
  - Used by APIs such as Amazon Transcribe streaming and Bedrock bidirectional
    streaming

### Changed

- **Minimum Elixir is now `~> 1.15`** (was `~> 1.14`). The optional `req`
  dependency pulls in `finch`, which dropped Elixir 1.14 support as of 0.22.
- Updated dependencies to latest and pruned stale unused lockfile entries
  inherited from the original `aws_auth`.
- CI now tests Elixir 1.20 / OTP 29 as the primary target.

---

## [1.3.1] - 2025-01-18

### Changed

- Updated Elixir to 1.19.2 and Erlang to 28.1.1
- Updated ex_doc to 0.39.1
- Updated CI test matrix to use latest tooling versions

---

## [1.3.0] - 2025-01-17

### Added

- **Service and region auto-detection from AWS URLs**
  - Pass `nil` as service to automatically detect from URL (e.g., `https://s3.us-west-2.amazonaws.com`)
  - Region is auto-detected from URL if not provided in credentials or options
  - Supports standard AWS service patterns (service.region.amazonaws.com)

- **Presigned URL expiration control**
  - `:expires_in` option for customizing presigned URL validity period
  - Default: 900 seconds (15 minutes), maximum: 604800 seconds (7 days)
  - Changed default expiration from 86400 (24 hours) to 900 (15 minutes) to match AWS SDK conventions

- **Unsigned payload support for streaming**
  - `:unsigned` atom can now be passed as `payload` parameter
  - Useful for large file uploads where content isn't known upfront
  - Automatically sets payload to "UNSIGNED-PAYLOAD" in signature

- **Advanced signing options**
  - `:unsigned_headers` - Exclude specific headers from signing (e.g., `["user-agent"]`)
  - `:uri_escape_path` - Control URI path escaping (default: `true`)
  - `:apply_checksum_header` - Control inclusion of `x-amz-content-sha256` header (default: `true`)

### Changed

- **Breaking**: Default presigned URL expiration reduced from 24 hours to 15 minutes
  - This aligns with AWS SDK defaults and security best practices
  - Explicitly set `:expires_in` if you need longer expiration times
- Internal header filtering now accepts a custom unsigned-headers list
- Internal canonical-request building now supports URI path escaping control
- All legacy API signatures remain fully backward compatible with new optional parameters

---

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

### Migration Guide (1.2.0)

```elixir
# Positional API (still supported)
AWSAuth.sign_authorization_header(
  access_key,
  secret_key,
  "POST",
  url,
  "us-east-1",
  "bedrock",
  headers,
  body,
  NaiveDateTime.utc_now(),
  session_token
)

# Credential struct API
creds = AWSAuth.Credentials.from_env()
AWSAuth.sign_authorization_header(creds, "POST", url, "bedrock", headers: headers, payload: body)

# Req plugin
Req.new(url: url, method: :post, body: body)
|> AWSAuth.Req.attach(credentials: creds, service: "bedrock")
|> Req.request()
```

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
- Migrated from deprecated Mix.Config to import Config

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
