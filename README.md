# ex_aws_auth

[![Hex.pm](https://img.shields.io/hexpm/v/ex_aws_auth)](https://hex.pm/packages/ex_aws_auth)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-purple)](https://hexdocs.pm/ex_aws_auth)
[![CI](https://github.com/neilberkman/ex_aws_auth/actions/workflows/elixir.yml/badge.svg)](https://github.com/neilberkman/ex_aws_auth/actions)

AWS Signature Version 4 signing library for Elixir. Small, focused, and easy to use.

## Features

- **Req Plugin**: Automatic request signing for the [Req](https://github.com/wojtekmach/req) HTTP client
- **Clean API**: Modern credential struct-based interface
- **Session Tokens**: Full support for temporary AWS credentials (STS)
- **Flexible Output**: Choose between list, map, or Req-compatible header formats
- **Backward Compatible**: Maintains compatibility with the original `aws_auth` API

## Installation

Add `ex_aws_auth` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_aws_auth, "~> 1.2"},
    {:req, "~> 0.5"}  # Optional, for Req plugin
  ]
end
```

## Quick Start

### With Req (Recommended)

The easiest way to use this library is with the Req plugin:

```elixir
# Load credentials from environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, etc.)
creds = AWSAuth.Credentials.from_env()

# Make authenticated requests
Req.new(url: "https://s3.amazonaws.com/my-bucket/file.txt")
|> AWSAuth.Req.attach(credentials: creds, service: "s3")
|> Req.get!()

# POST with body
Req.new(url: "https://bedrock-runtime.us-east-1.amazonaws.com/model/my-model/invoke")
|> AWSAuth.Req.attach(credentials: creds, service: "bedrock")
|> Req.post!(json: %{prompt: "Hello"})
```

### Manual Signing

For manual control over request signing:

```elixir
# Create credentials
creds = %AWSAuth.Credentials{
  access_key_id: "AKIAIOSFODNN7EXAMPLE",
  secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  region: "us-east-1"
}

# Sign a URL (for presigned URLs)
signed_url = AWSAuth.sign_url(
  creds,
  "GET",
  "https://s3.amazonaws.com/my-bucket/file.txt",
  "s3"
)

# Sign request headers (for API calls)
headers = AWSAuth.sign_authorization_header(
  creds,
  "POST",
  "https://bedrock-runtime.us-east-1.amazonaws.com/model/my-model/invoke",
  "bedrock",
  headers: %{"content-type" => "application/json"},
  payload: Jason.encode!(%{prompt: "Hello"})
)
```

## Credentials

### From Environment Variables

```elixir
# Reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION
creds = AWSAuth.Credentials.from_env()
```

### Manual Creation

```elixir
creds = %AWSAuth.Credentials{
  access_key_id: "AKIAIOSFODNN7EXAMPLE",
  secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  session_token: "FwoGZXIvYXdzEBYa...",  # Optional, for STS temporary credentials
  region: "us-east-1"
}
```

### From Map or Keyword List

```elixir
creds = AWSAuth.Credentials.from_map(%{
  access_key_id: "...",
  secret_access_key: "...",
  region: "us-west-2"
})
```

## Advanced Usage

### Session Tokens (STS Temporary Credentials)

Full support for AWS Security Token Service temporary credentials:

```elixir
creds = %AWSAuth.Credentials{
  access_key_id: "ASIAIOSFODNN7EXAMPLE",  # Note: Starts with ASIA for temporary creds
  secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  session_token: "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123",
  region: "us-east-1"
}

# Automatically includes X-Amz-Security-Token in signatures
Req.new(url: url)
|> AWSAuth.Req.attach(credentials: creds, service: "s3")
|> Req.get!()
```

### Header Format Options

Choose your preferred header format:

```elixir
# List of tuples (default, works with most HTTP clients)
headers = AWSAuth.sign_authorization_header(creds, method, url, service,
  return_format: :list
)
# => [{"authorization", "AWS4-HMAC-SHA256 ..."}, {"x-amz-date", "..."}]

# Map (convenient for merging)
headers = AWSAuth.sign_authorization_header(creds, method, url, service,
  return_format: :map
)
# => %{"authorization" => "AWS4-HMAC-SHA256 ...", "x-amz-date" => "..."}

# Req format (for use with Req)
headers = AWSAuth.sign_authorization_header(creds, method, url, service,
  return_format: :req
)
# => %{"authorization" => ["AWS4-HMAC-SHA256 ..."], "x-amz-date" => ["..."]}
```

### Region Override

```elixir
# Override the region from credentials
AWSAuth.sign_url(creds, "GET", url, "s3", region: "eu-west-1")
```

## Legacy API (Backward Compatibility)

The original `aws_auth` API is still supported for backward compatibility:

```elixir
# Old-style URL signing (still works)
signed_url = AWSAuth.sign_url(
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "GET",
  "https://examplebucket.s3.amazonaws.com/test.txt",
  "us-east-1",
  "s3"
)

# Old-style header signing (still works)
auth_header = AWSAuth.sign_authorization_header(
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "PUT",
  "https://examplebucket.s3.amazonaws.com/test.txt",
  "us-east-1",
  "s3",
  %{"x-amz-storage-class" => "REDUCED_REDUNDANCY"},
  "file contents"
)
```

**Note:** While the legacy API is fully supported, we recommend using the new Credentials-based API or Req plugin for new projects.

## Why `ex_aws_auth`?

The original `aws_auth` package was created by [**Bryan Joseph**](https://github.com/bryanjos). Unfortunately, it is no longer actively maintained and has become incompatible with modern versions of Erlang/OTP.

[**Rodrigo Zampieri Castilho**](https://github.com/rzcastilho) forked it and brought it up to date for OTP 27, but his fork cannot be included as a dependency in packages published on Hex.

This package, `ex_aws_auth`, is published on Hex to make this essential AWS signing functionality available to the broader Elixir community, with modern improvements and active maintenance.

Full credit and thanks go to Bryan Joseph for creating the original library and Rodrigo Zampieri Castilho for maintaining compatibility with modern OTP versions.

## Documentation

Full documentation is available on [HexDocs](https://hexdocs.pm/ex_aws_auth).

## License

Apache License 2.0 - See LICENSE file for details.
