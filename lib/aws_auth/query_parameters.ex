defmodule AWSAuth.QueryParameters do
  @moduledoc false

  # http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
  def sign(
        access_key,
        secret_key,
        http_method,
        url,
        region,
        service,
        headers,
        request_time,
        payload,
        session_token \\ nil,
        opts \\ []
      ) do
    uri = URI.parse(url)

    http_method = String.upcase(http_method)
    region = String.downcase(region)
    service = to_string(service)

    unsigned_headers = Keyword.get(opts, :unsigned_headers, [])
    expires_in = opts |> Keyword.get(:expires_in, 900) |> normalize_expires_in!()
    uri_escape_path = resolve_uri_escape_path(opts, service)

    headers =
      headers
      |> AWSAuth.Utils.normalize_headers()
      |> Map.drop(["x-amz-security-token", "x-amz-s3session-token"])
      |> Map.put_new("host", AWSAuth.Utils.host_header(uri))

    {to_sign, _passthrough} = AWSAuth.Utils.split_unsigned_headers(headers, unsigned_headers)

    amz_date = AWSAuth.Utils.format_time(request_time)
    date = AWSAuth.Utils.format_date(request_time)

    scope = "#{date}/#{region}/#{service}/aws4_request"

    params =
      case uri.query do
        nil ->
          []

        _ ->
          uri.query
          |> URI.query_decoder()
          |> Enum.reject(fn {key, _value} ->
            key in ["X-Amz-Signature", "X-Amz-Security-Token", "X-Amz-S3session-Token"]
          end)
      end

    params =
      params
      |> put_param("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
      |> put_param("X-Amz-Credential", "#{access_key}/#{scope}")
      |> put_param("X-Amz-Date", amz_date)
      |> put_param("X-Amz-Expires", to_string(expires_in))
      |> put_param("X-Amz-SignedHeaders", AWSAuth.Utils.signed_headers(to_sign))

    s3express_session =
      Keyword.get(opts, :auth_scheme) == :s3express_session or
        Keyword.get(opts, :s3express_session, false) == true

    token_param =
      if s3express_session,
        do: "X-Amz-S3session-Token",
        else: "X-Amz-Security-Token"

    params =
      if session_token do
        put_param(params, token_param, session_token)
      else
        params
      end

    hashed_payload =
      if AWSAuth.Utils.s3_family?(service),
        do: :unsigned,
        else: AWSAuth.Utils.hash_sha256(payload)

    string_to_sign =
      AWSAuth.Utils.build_canonical_request(
        http_method,
        uri.path || "/",
        params,
        to_sign,
        hashed_payload,
        uri_escape_path
      )
      |> AWSAuth.Utils.build_string_to_sign(amz_date, scope)

    signature =
      AWSAuth.Utils.build_signing_key(secret_key, date, region, service)
      |> AWSAuth.Utils.build_signature(string_to_sign)

    params = put_param(params, "X-Amz-Signature", signature)
    query_string = AWSAuth.Utils.canonical_query_string(params)

    "#{uri.scheme}://#{uri.authority}#{uri.path || "/"}?#{query_string}"
  end

  defp resolve_uri_escape_path(opts, service) do
    case Keyword.fetch(opts, :uri_escape_path) do
      {:ok, value} when is_boolean(value) -> value
      _ -> not AWSAuth.Utils.s3_family?(service)
    end
  end

  defp put_param(params, key, value) do
    [{key, value} | Enum.reject(params, fn {existing_key, _value} -> existing_key == key end)]
  end

  defp normalize_expires_in!(expires_in)
       when is_integer(expires_in) and expires_in >= 1 and expires_in <= 604_800, do: expires_in

  defp normalize_expires_in!(expires_in) when is_binary(expires_in) do
    case Integer.parse(expires_in) do
      {value, ""} -> normalize_expires_in!(value)
      _other -> invalid_expires_in!(expires_in)
    end
  end

  defp normalize_expires_in!(expires_in), do: invalid_expires_in!(expires_in)

  defp invalid_expires_in!(expires_in) do
    raise ArgumentError,
          ":expires_in must be an integer between 1 and 604800 seconds, got: #{inspect(expires_in)}"
  end
end
