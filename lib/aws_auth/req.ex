if Code.ensure_loaded?(Req.Request) do
  defmodule AWSAuth.Req do
    @moduledoc """
    Req plugin for AWS Signature V4 authentication.

    This module provides seamless integration between `ex_aws_auth` and the
    `Req` HTTP client library. It automatically signs requests with AWS Signature V4
    without requiring manual header manipulation.

    ## Usage

        # Load credentials from environment
        creds = AWSAuth.Credentials.from_env()

        # Attach to a Req request
        Req.new(url: url, method: :post, body: body)
        |> AWSAuth.Req.attach(credentials: creds, service: "bedrock")
        |> Req.request()

        # Or create a reusable client
        client =
          Req.new(base_url: "https://bedrock-runtime.us-east-1.amazonaws.com")
          |> AWSAuth.Req.attach(credentials: creds, service: "bedrock")

        # Make multiple requests
        Req.post!(client, url: "/model/my-model/invoke", json: params)

    ## Options

      * `:credentials` - (required) `AWSAuth.Credentials` struct or keyword list/map with:
        * `:access_key_id` - AWS Access Key ID
        * `:secret_access_key` - AWS Secret Access Key
        * `:session_token` - AWS Session Token (optional)
        * `:region` - AWS region (optional, fallback when URL has no region)

      * `:service` - (required) AWS service name (e.g., "s3", "bedrock", "lambda")

      * `:region` - AWS region (optional; overrides URL and credentials region)

      * `:unsigned_headers` - List of header names to exclude from signing (optional)

      * `:uri_escape_path` - Override URI path escaping (optional)

      * `:apply_checksum_header` - Include `x-amz-content-sha256` header (optional, default: `true`)

      * `:payload` - Force `:unsigned` or `:streaming_events` payload mode (optional)

      * `:auth_scheme` - Authentication scheme (`:sigv4` or `:s3express_session`; when `:s3express_session`, emits `x-amz-s3session-token` instead of `x-amz-security-token`, optional, default: `:sigv4`)

    ## How it Works

    The plugin adds a request step that:

    1. Resolves the signing region (`explicit :region` > URL > `credentials.region` > `"us-east-1"`)
    2. Signs the request using AWS Signature V4
    3. Tracks generated headers (`authorization`, `x-amz-date`, `x-amz-content-sha256`, `x-amz-security-token`, and `host` when not caller-supplied) so retries and trusted redirects re-sign cleanly
    4. On a cross-origin redirect, strips the signing headers, `host`, and every caller-supplied `x-amz-*` header and does not re-sign. With `redirect_trusted: true` on the request, a redirect to an `https` endpoint of the same AWS service (for example an S3 region redirect) is re-signed instead; a redirect to any other host, or to plain `http`, is still stripped. The endpoint is recognized from its hostname, so hosts that `AWSAuth` cannot map to a service (API Gateway, OpenSearch domains, Lambda function URLs, non-AWS S3-compatible servers) are never re-signed across origins.

    A streamed request body is signed as `UNSIGNED-PAYLOAD`. Over `https` this is
    automatic; over plain `http` it raises unless `payload: :unsigned` is passed.

    Attach this plugin after any custom plugin that changes the request URL, body,
    or headers. Request steps appended after AWS signing may make the signature stale.
    """

    alias AWSAuth.Credentials

    @valid_options [
      :credentials,
      :service,
      :region,
      :unsigned_headers,
      :uri_escape_path,
      :apply_checksum_header,
      :payload,
      :auth_scheme,
      :s3express_session
    ]

    @credential_headers [
      "authorization",
      "x-amz-content-sha256",
      "x-amz-date",
      "x-amz-security-token",
      "x-amz-s3session-token"
    ]

    @doc """
    Attaches AWS Signature V4 signing to a Req request.

    ## Parameters

      * `request` - A `Req.Request` struct
      * `opts` - Keyword list of options (see module docs for details)

    ## Returns

    A `Req.Request` with the AWS signing step appended after Req prepares the URL and body.
    """
    @spec attach(Req.Request.t(), keyword()) :: Req.Request.t()
    def attach(%Req.Request{} = request, opts) when is_list(opts) do
      _validated = Keyword.validate!(opts, @valid_options)
      credentials = get_credentials!(opts)
      service = get_service!(opts)
      explicit_region = Keyword.get(opts, :region)
      payload_opt = get_payload_opt!(opts)

      signing_opts =
        Keyword.take(opts, [
          :unsigned_headers,
          :uri_escape_path,
          :apply_checksum_header,
          :auth_scheme,
          :s3express_session
        ])

      Req.Request.append_request_steps(
        request,
        aws_sigv4: fn req ->
          sign_request(req, credentials, service, explicit_region, payload_opt, signing_opts)
        end
      )
    end

    defp sign_request(req, credentials, service, explicit_region, payload_opt, signing_opts) do
      prev_generated = Req.Request.get_private(req, :aws_sigv4_generated, [])
      current_origin = request_origin(req.url)
      prev_origin = Req.Request.get_private(req, :aws_sigv4_origin)
      origin_changed? = prev_origin != nil and prev_origin != current_origin
      redirect_trusted? = Req.Request.get_option(req, :redirect_trusted, false) == true

      # `redirect_trusted: true` re-signs across origins only for an `https`
      # endpoint of the same AWS service; credentials are never signed for an
      # arbitrary host a redirect points at, nor sent over plain HTTP.
      resign_cross_origin? = redirect_trusted? and same_service_endpoint?(req.url, service)

      untrusted_redirect? =
        Req.Request.get_private(req, :aws_sigv4_untrusted_redirect, false) or
          (origin_changed? and not resign_cross_origin?)

      if untrusted_redirect? do
        stripped_headers =
          req.headers
          |> drop_headers_case_insensitive(@credential_headers ++ ["host" | prev_generated])
          |> drop_amz_headers()

        req
        |> Map.put(:headers, stripped_headers)
        |> Req.Request.put_private(:aws_sigv4_untrusted_redirect, true)
        |> Req.Request.put_private(:aws_sigv4_generated, [])
      else
        names_to_drop =
          if origin_changed? do
            @credential_headers ++ ["host" | prev_generated]
          else
            @credential_headers ++ prev_generated
          end

        caller_headers = drop_headers_case_insensitive(req.headers, names_to_drop)
        method = String.upcase(to_string(req.method))
        url = URI.to_string(req.url)
        region = AWSAuth.resolve_region(explicit_region, url, credentials)
        payload = resolve_payload!(req.body, caller_headers, payload_opt, req.url.scheme)

        caller_header_names =
          caller_headers
          |> Map.keys()
          |> MapSet.new(&String.downcase(to_string(&1), :ascii))

        signed_headers =
          AWSAuth.sign_authorization_header(
            credentials,
            method,
            url,
            service,
            [
              headers: caller_headers,
              payload: payload,
              region: region,
              return_format: :req
            ] ++ signing_opts
          )

        generated_names =
          signed_headers
          |> Map.keys()
          |> Enum.reject(&MapSet.member?(caller_header_names, &1))

        req
        |> Map.put(:headers, signed_headers)
        |> Req.Request.put_private(:aws_sigv4_origin, current_origin)
        |> Req.Request.put_private(:aws_sigv4_generated, generated_names)
      end
    end

    defp drop_headers_case_insensitive(headers, names_to_drop) do
      drop_set = MapSet.new(names_to_drop, &String.downcase(to_string(&1), :ascii))

      Map.reject(headers, fn {key, _value} ->
        MapSet.member?(drop_set, String.downcase(to_string(key), :ascii))
      end)
    end

    # Caller-supplied `x-amz-*` headers can carry secrets (for example SSE-C keys)
    # and are only meaningful to the endpoint that was signed for.
    defp drop_amz_headers(headers) do
      Map.reject(headers, fn {key, _value} ->
        key |> to_string() |> String.downcase(:ascii) |> String.starts_with?("x-amz-")
      end)
    end

    # Hostnames under `amazonaws.com` are not all AWS API endpoints (EC2 public
    # DNS, S3 website endpoints), so the host has to resolve to the service this
    # request is being signed for, not merely look like AWS.
    defp same_service_endpoint?(%URI{scheme: "https"} = url, service) do
      case AWSAuth.Utils.parse_aws_url(url) do
        {detected, _region} when is_binary(detected) ->
          detected == service or
            (AWSAuth.Utils.s3_family?(detected) and AWSAuth.Utils.s3_family?(service))

        _other ->
          false
      end
    end

    defp same_service_endpoint?(%URI{}, _service), do: false

    defp request_origin(%URI{scheme: scheme, host: host, port: port}) do
      normalized_host = if is_binary(host), do: String.downcase(host, :ascii)
      {scheme, normalized_host, port || URI.default_port(scheme)}
    end

    defp resolve_payload!(_body, _headers, :streaming_events, _scheme), do: :streaming_events

    defp resolve_payload!(body, _headers, :unsigned, _scheme)
         when is_nil(body) or is_binary(body) or is_list(body) do
      :unsigned
    end

    defp resolve_payload!(nil, _headers, nil, _scheme), do: ""

    defp resolve_payload!(body, _headers, nil, _scheme) when is_binary(body) or is_list(body),
      do: body

    defp resolve_payload!(_stream_body, headers, payload_opt, scheme) do
      # A streamed body is sent as UNSIGNED-PAYLOAD. Over plain HTTP nothing else
      # protects the body, so the caller has to opt in.
      if scheme != "https" and payload_opt != :unsigned do
        raise ArgumentError,
              "streaming a request body over #{inspect(scheme)} sends it unsigned; " <>
                "pass payload: :unsigned to AWSAuth.Req.attach/2 to allow this"
      end

      has_content_length? =
        Enum.any?(headers, fn {key, value} ->
          String.downcase(to_string(key), :ascii) == "content-length" and
            value not in [[], "", nil]
        end)

      if !has_content_length? do
        raise ArgumentError, "content-length header must be set when streaming a request body"
      end

      :unsigned
    end

    defp get_payload_opt!(opts) do
      case Keyword.get(opts, :payload) do
        nil ->
          nil

        mode when mode in [:unsigned, :streaming_events] ->
          mode

        other ->
          raise ArgumentError,
                "Invalid :payload option. Expected :unsigned or :streaming_events, got: #{inspect(other)}"
      end
    end

    defp get_credentials!(opts) do
      case Keyword.fetch(opts, :credentials) do
        {:ok, %Credentials{} = creds} ->
          creds

        {:ok, creds} when is_list(creds) or is_map(creds) ->
          Credentials.from_map(creds)

        :error ->
          raise ArgumentError, """
          Missing required :credentials option.

          Please provide credentials as either:

          1. AWSAuth.Credentials struct:
             AWSAuth.Req.attach(request, credentials: AWSAuth.Credentials.from_env(), service: "s3")

          2. Keyword list or map:
             AWSAuth.Req.attach(request,
               credentials: [
                 access_key_id: "...",
                 secret_access_key: "...",
                 region: "us-east-1"
               ],
               service: "s3"
             )
          """
      end
    end

    defp get_service!(opts) do
      case Keyword.fetch(opts, :service) do
        {:ok, service} when is_binary(service) ->
          service

        {:ok, other} ->
          raise ArgumentError, """
          Invalid :service option. Expected a string, got: #{inspect(other)}

          Example:
            AWSAuth.Req.attach(request, credentials: creds, service: "bedrock")
          """

        :error ->
          raise ArgumentError, """
          Missing required :service option.

          Please specify the AWS service name:
            AWSAuth.Req.attach(request, credentials: creds, service: "bedrock")

          Common services: "s3", "bedrock", "lambda", "dynamodb", "sns", "sqs"
          """
      end
    end
  end
end
