defmodule AWSAuth.AuthorizationHeader do
  @moduledoc false

  # http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
  def sign(
        access_key,
        secret_key,
        http_method,
        url,
        region,
        service,
        payload,
        headers,
        request_time,
        session_token \\ nil,
        opts \\ []
      ) do
    uri = URI.parse(url)

    params =
      case uri.query do
        nil -> []
        query -> Enum.to_list(URI.query_decoder(query))
      end

    http_method = String.upcase(http_method)
    region = String.downcase(region)
    service = to_string(service)

    unsigned_headers = Keyword.get(opts, :unsigned_headers, [])
    uri_escape_path = resolve_uri_escape_path(opts, service)
    apply_checksum_header = Keyword.get(opts, :apply_checksum_header, true)

    headers =
      headers
      |> AWSAuth.Utils.normalize_headers()
      |> Map.drop(["x-amz-security-token", "x-amz-s3session-token"])
      |> Map.put_new("host", AWSAuth.Utils.host_header(uri))

    s3express_session =
      Keyword.get(opts, :auth_scheme) == :s3express_session or
        Keyword.get(opts, :s3express_session, false) == true

    token_header =
      if s3express_session,
        do: "x-amz-s3session-token",
        else: "x-amz-security-token"

    headers =
      if session_token do
        Map.put(
          headers,
          token_header,
          AWSAuth.Utils.normalize_header_value(session_token)
        )
      else
        headers
      end

    hashed_payload = hashed_payload(payload)

    headers =
      if apply_checksum_header do
        checksum_value =
          if hashed_payload == :unsigned, do: "UNSIGNED-PAYLOAD", else: hashed_payload

        Map.put_new(headers, "x-amz-content-sha256", checksum_value)
      else
        headers
      end

    amz_date = AWSAuth.Utils.format_time(request_time)
    date = AWSAuth.Utils.format_date(request_time)

    headers = Map.put_new(headers, "x-amz-date", amz_date)

    {to_sign, passthrough} = AWSAuth.Utils.split_unsigned_headers(headers, unsigned_headers)

    scope = "#{date}/#{region}/#{service}/aws4_request"

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

    signed_headers = AWSAuth.Utils.signed_headers(to_sign)

    auth_header =
      "AWS4-HMAC-SHA256 Credential=#{access_key}/#{scope},SignedHeaders=#{signed_headers},Signature=#{signature}"

    to_sign
    |> Map.merge(passthrough)
    |> Map.put("authorization", auth_header)
    |> Map.to_list()
  end

  defp resolve_uri_escape_path(opts, service) do
    case Keyword.fetch(opts, :uri_escape_path) do
      {:ok, value} when is_boolean(value) -> value
      _ -> not AWSAuth.Utils.s3_family?(service)
    end
  end

  defp hashed_payload(:unsigned), do: :unsigned
  defp hashed_payload(:streaming_events), do: "STREAMING-AWS4-HMAC-SHA256-EVENTS"
  defp hashed_payload(payload), do: AWSAuth.Utils.hash_sha256(payload)
end
