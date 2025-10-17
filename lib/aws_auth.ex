defmodule AWSAuth do
  @moduledoc """
  Signs urls or authentication headers for use with AWS requests.

  ## New in 1.2.0

  This version adds convenient new APIs while maintaining 100% backward compatibility:

  - `AWSAuth.Credentials` struct for cleaner credential management
  - Credential struct overloads for `sign_url` and `sign_authorization_header`
  - Optional `return_format` option (`:list`, `:map`, `:req`) for flexible header formats
  - `AWSAuth.Req` plugin for seamless Req integration

  ## Migration Guide

  ### Old API (still fully supported)
  ```elixir
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
  ```

  ### New credential struct API
  ```elixir
  creds = %AWSAuth.Credentials{
    access_key_id: access_key,
    secret_access_key: secret_key,
    session_token: session_token,
    region: "us-east-1"
  }

  # Or load from environment
  creds = AWSAuth.Credentials.from_env()

  # Simpler function call
  AWSAuth.sign_authorization_header(
    creds,
    "POST",
    url,
    "bedrock",
    headers,
    body
  )
  ```

  ### With Req plugin
  ```elixir
  creds = AWSAuth.Credentials.from_env()

  Req.new(url: url, method: :post, body: body)
  |> AWSAuth.Req.attach(credentials: creds, service: "bedrock")
  |> Req.request()
  ```
  """

  alias AWSAuth.Credentials

  @doc """
  Signs a URL using AWS Signature V4 with a Credentials struct.

  This is a convenience overload that accepts an `AWSAuth.Credentials` struct.

  ## Parameters

    * `credentials` - `AWSAuth.Credentials` struct with AWS credentials
    * `http_method` - HTTP method as string ("GET", "POST", etc)
    * `url` - The AWS URL to sign
    * `service` - AWS service name (e.g., "s3", "bedrock")
    * `opts` - Keyword list of options:
      * `:headers` - Request headers (default: `%{}`)
      * `:payload` - Request body (default: `""`)
      * `:timestamp` - `NaiveDateTime` for signing (default: current time)
      * `:region` - Override region from credentials

  ## Examples

      creds = AWSAuth.Credentials.from_env()
      signed_url = AWSAuth.sign_url(creds, "GET", url, "s3")

      # With options
      signed_url = AWSAuth.sign_url(
        creds,
        "POST",
        url,
        "bedrock",
        headers: %{"content-type" => "application/json"},
        payload: Jason.encode!(data)
      )
  """
  def sign_url(%Credentials{} = creds, http_method, url, service, opts \\ []) do
    headers = Keyword.get(opts, :headers, %{})
    payload = Keyword.get(opts, :payload, "")
    timestamp = Keyword.get(opts, :timestamp, current_time())
    region = Keyword.get(opts, :region, creds.region || "us-east-1")

    sign_url(
      creds.access_key_id,
      creds.secret_access_key,
      http_method,
      url,
      region,
      service,
      headers,
      timestamp,
      payload,
      creds.session_token
    )
  end

  @doc """
  `AWSAuth.sign_url(access_key, secret_key, http_method, url, region, service, headers, request_time, payload, session_token)`

  `access_key`: Your AWS Access key

  `secret_key`: Your AWS secret key

  `http_method`: "GET","POST","PUT","DELETE", etc

  `url`: The AWS url you want to sign

  `region`: The AWS name for the region you want to access (i.e. us-east-1). Check [here](http://docs.aws.amazon.com/general/latest/gr/rande.html) for the region names

  `service`: The AWS service you are trying to access (i.e. s3). Check the url above for names as well.

  `headers` (optional. defaults to `Map.new`): The headers that will be used in the request. Used for signing the request.
  For signing, host is the only one required unless using any other x-amx-* headers.
  If host is present here, it will override using the host in the url to attempt signing.
  If only the host is needed, then you don't have to supply it and the host from the url will be used.

  `request_time` (optional): NaiveDateTime for the request timestamp. Defaults to current time.

  `payload` (optional. defaults to `""`): The contents of the payload if there is one.

  `session_token` (optional. defaults to `nil`): AWS session token for temporary credentials (from STS).
  When provided, adds the X-Amz-Security-Token header to the signed request.
  """
  def sign_url(access_key, secret_key, http_method, url, region, service) do
    sign_url(access_key, secret_key, http_method, url, region, service, Map.new())
  end

  def sign_url(access_key, secret_key, http_method, url, region, service, headers) do
    sign_url(access_key, secret_key, http_method, url, region, service, headers, current_time())
  end

  def sign_url(access_key, secret_key, http_method, url, region, service, headers, request_time) do
    sign_url(access_key, secret_key, http_method, url, region, service, headers, request_time, "")
  end

  def sign_url(
        access_key,
        secret_key,
        http_method,
        url,
        region,
        service,
        headers,
        request_time,
        payload
      ) do
    sign_url(
      access_key,
      secret_key,
      http_method,
      url,
      region,
      service,
      headers,
      request_time,
      payload,
      nil
    )
  end

  def sign_url(
        access_key,
        secret_key,
        http_method,
        url,
        region,
        service,
        headers,
        request_time,
        payload,
        session_token
      ) do
    AWSAuth.QueryParameters.sign(
      access_key,
      secret_key,
      http_method,
      url,
      region,
      service,
      headers,
      request_time,
      payload,
      session_token
    )
  end

  @doc """
  Signs request headers using AWS Signature V4 with a Credentials struct.

  This is a convenience overload that accepts an `AWSAuth.Credentials` struct.

  ## Parameters

    * `credentials` - `AWSAuth.Credentials` struct with AWS credentials
    * `http_method` - HTTP method as string ("GET", "POST", etc)
    * `url` - The AWS URL to sign
    * `service` - AWS service name (e.g., "s3", "bedrock")
    * `headers` - Request headers as map (default: `%{}`)
    * `payload` - Request body (default: `""`)
    * `opts` - Keyword list of options:
      * `:timestamp` - `NaiveDateTime` for signing (default: current time)
      * `:region` - Override region from credentials
      * `:return_format` - Return format (`:list`, `:map`, `:req`) (default: `:list`)

  ## Return Formats

    * `:list` - (default) Returns list of tuples `[{"header", "value"}]`
    * `:map` - Returns map `%{"header" => "value"}`
    * `:req` - Returns Req-compatible map `%{"header" => ["value"]}`

  ## Examples

      creds = AWSAuth.Credentials.from_env()

      # Returns list of tuples (default)
      headers = AWSAuth.sign_authorization_header(creds, "POST", url, "bedrock", %{}, body)
      # => [{"authorization", "AWS4-HMAC-SHA256 ..."}, {"x-amz-date", "..."}]

      # Return as map
      headers = AWSAuth.sign_authorization_header(
        creds,
        "POST",
        url,
        "bedrock",
        %{"content-type" => "application/json"},
        body,
        return_format: :map
      )
      # => %{"authorization" => "AWS4-HMAC-SHA256 ...", "x-amz-date" => "..."}

      # Return in Req format
      headers = AWSAuth.sign_authorization_header(
        creds,
        "POST",
        url,
        "bedrock",
        %{},
        body,
        return_format: :req
      )
      # => %{"authorization" => ["AWS4-HMAC-SHA256 ..."], "x-amz-date" => ["..."]}
  """
  def sign_authorization_header(%Credentials{} = creds, http_method, url, service, opts \\ [])
      when is_list(opts) do
    headers = Keyword.get(opts, :headers, %{})
    payload = Keyword.get(opts, :payload, "")
    timestamp = Keyword.get(opts, :timestamp, current_time())
    region = Keyword.get(opts, :region, creds.region || "us-east-1")
    return_format = Keyword.get(opts, :return_format, :list)

    signed_headers =
      sign_authorization_header(
        creds.access_key_id,
        creds.secret_access_key,
        http_method,
        url,
        region,
        service,
        headers,
        payload,
        timestamp,
        creds.session_token
      )

    format_headers(signed_headers, return_format)
  end

  @doc """
  `AWSAuth.sign_authorization_header(access_key, secret_key, http_method, url, region, service, headers, payload, request_time, session_token)`

  `access_key`: Your AWS Access key

  `secret_key`: Your AWS secret key

  `http_method`: "GET","POST","PUT","DELETE", etc

  `url`: The AWS url you want to sign

  `region`: The AWS name for the region you want to access (i.e. us-east-1). Check [here](http://docs.aws.amazon.com/general/latest/gr/rande.html) for the region names

  `service`: The AWS service you are trying to access (i.e. s3). Check the url above for names as well.

  `headers` (optional. defaults to `Map.new`): The headers that will be used in the request. Used for signing the request.
  For signing, host is the only one required unless using any other x-amx-* headers.
  If host is present here, it will override using the host in the url to attempt signing.
  Same goes for the x-amz-content-sha256 headers
  If only the host and x-amz-content-sha256 headers are needed, then you don't have to supply it and the host from the url will be used and
  the payload will be hashed to get the x-amz-content-sha256 header.

  `payload` (optional. defaults to `""`): The contents of the payload if there is one.

  `request_time` (optional): NaiveDateTime for the request timestamp. Defaults to current time.

  `session_token` (optional. defaults to `nil`): AWS session token for temporary credentials (from STS).
  When provided, adds the X-Amz-Security-Token header to the signed request.
  """
  def sign_authorization_header(access_key, secret_key, http_method, url, region, service) do
    sign_authorization_header(
      access_key,
      secret_key,
      http_method,
      url,
      region,
      service,
      Map.new()
    )
  end

  def sign_authorization_header(
        access_key,
        secret_key,
        http_method,
        url,
        region,
        service,
        headers
      ) do
    sign_authorization_header(
      access_key,
      secret_key,
      http_method,
      url,
      region,
      service,
      headers,
      ""
    )
  end

  def sign_authorization_header(
        access_key,
        secret_key,
        http_method,
        url,
        region,
        service,
        headers,
        payload
      ) do
    sign_authorization_header(
      access_key,
      secret_key,
      http_method,
      url,
      region,
      service,
      headers,
      payload,
      current_time()
    )
  end

  def sign_authorization_header(
        access_key,
        secret_key,
        http_method,
        url,
        region,
        service,
        headers,
        payload,
        request_time
      ) do
    sign_authorization_header(
      access_key,
      secret_key,
      http_method,
      url,
      region,
      service,
      headers,
      payload,
      request_time,
      nil
    )
  end

  def sign_authorization_header(
        access_key,
        secret_key,
        http_method,
        url,
        region,
        service,
        headers,
        payload,
        request_time,
        session_token
      ) do
    AWSAuth.AuthorizationHeader.sign(
      access_key,
      secret_key,
      http_method,
      url,
      region,
      service,
      payload,
      headers,
      request_time,
      session_token
    )
  end

  # Format signed headers into different return formats
  defp format_headers(headers, :list), do: headers
  defp format_headers(headers, :map), do: Map.new(headers)
  defp format_headers(headers, :req), do: Map.new(headers, fn {k, v} -> {k, [v]} end)

  defp current_time do
    DateTime.utc_now() |> DateTime.to_naive()
  end
end
