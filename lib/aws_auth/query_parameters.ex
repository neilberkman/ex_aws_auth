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
    service = String.downcase(service)

    headers =
      headers
      |> AWSAuth.Utils.filter_unsignable_headers()
      |> AWSAuth.Utils.normalize_header_values()
      |> Map.put_new("host", uri.host)

    amz_date = request_time |> AWSAuth.Utils.format_time()
    date = request_time |> AWSAuth.Utils.format_date()

    scope = "#{date}/#{region}/#{service}/aws4_request"

    params =
      case uri.query do
        nil ->
          []

        _ ->
          Enum.to_list(URI.query_decoder(uri.query))
      end

    # Default expiration is 15 minutes (900 seconds), max is 7 days (604800 seconds)
    expires_in = opts |> Keyword.get(:expires_in, 900) |> normalize_expires_in!()
    uri_escape_path = Keyword.get(opts, :uri_escape_path, true)

    params =
      params
      |> put_param("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
      |> put_param("X-Amz-Credential", "#{access_key}/#{scope}")
      |> put_param("X-Amz-Date", amz_date)
      |> put_param("X-Amz-Expires", to_string(expires_in))
      |> put_param("X-Amz-SignedHeaders", AWSAuth.Utils.signed_headers(headers))

    # Add session token to query params if provided (for temporary credentials)
    params =
      if session_token do
        put_param(params, "X-Amz-Security-Token", session_token)
      else
        params
      end

    hashed_payload =
      if service == "s3",
        do: :unsigned,
        else: AWSAuth.Utils.hash_sha256(payload)

    string_to_sign =
      AWSAuth.Utils.build_canonical_request(
        http_method,
        uri.path || "/",
        params,
        headers,
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
