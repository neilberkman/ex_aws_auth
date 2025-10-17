defmodule AWSAuth.Utils do
  @moduledoc false

  @doc """
  Filters out headers that should not be included in signing.
  AWS infrastructure may add trace headers that would break the signature.
  """
  def filter_unsignable_headers(headers) do
    headers
    |> Enum.reject(fn {key, _value} ->
      String.downcase(key) == "x-amzn-trace-id"
    end)
    |> Map.new()
  end

  @doc """
  Normalizes header values by collapsing multiple consecutive spaces into a single space.
  This is required by AWS Signature V4 specification.
  """
  def normalize_header_values(headers) do
    headers
    |> Map.new(fn {key, value} ->
      normalized_value =
        value
        |> to_string()
        |> remove_dup_spaces()

      {key, normalized_value}
    end)
  end

  defp remove_dup_spaces(string) do
    case Regex.replace(~r/  +/, string, " ") do
      ^string -> string
      result -> remove_dup_spaces(result)
    end
  end

  @doc """
  Validates that query parameter keys and values are not lists.
  Lists in query parameters can cause encoding issues.
  """
  def validate_query_params(params) do
    Enum.each(params, fn {key, value} ->
      if is_list(key) or is_list(value) do
        raise ArgumentError,
              "Query parameter keys and values cannot be lists. Got: #{inspect(key)} => #{inspect(value)}"
      end
    end)

    params
  end

  def build_canonical_request(http_method, path, params, headers, hashed_payload) do
    validate_query_params(params)
    query_params = URI.encode_query(params) |> String.replace("+", "%20")

    header_params =
      Enum.map(headers, fn {key, value} -> "#{String.downcase(key)}:#{String.trim(value)}" end)
      |> Enum.sort(&(&1 < &2))
      |> Enum.join("\n")

    signed_header_params =
      Enum.map(headers, fn {key, _} -> String.downcase(key) end)
      |> Enum.sort(&(&1 < &2))
      |> Enum.join(";")

    hashed_payload =
      if hashed_payload == :unsigned,
        do: "UNSIGNED-PAYLOAD",
        else: hashed_payload

    encoded_path =
      path
      |> String.split("/")
      |> Enum.map_join("/", fn segment -> URI.encode_www_form(segment) end)

    "#{http_method}\n#{encoded_path}\n#{query_params}\n#{header_params}\n\n#{signed_header_params}\n#{hashed_payload}"
  end

  def build_string_to_sign(canonical_request, timestamp, scope) do
    hashed_canonical_request = hash_sha256(canonical_request)
    "AWS4-HMAC-SHA256\n#{timestamp}\n#{scope}\n#{hashed_canonical_request}"
  end

  def build_signing_key(secret_key, date, region, service) do
    hmac_sha256("AWS4#{secret_key}", date)
    |> hmac_sha256(region)
    |> hmac_sha256(service)
    |> hmac_sha256("aws4_request")
  end

  def build_signature(signing_key, string_to_sign) do
    hmac_sha256(signing_key, string_to_sign)
    |> bytes_to_string()
  end

  def hash_sha256(data) do
    :crypto.hash(:sha256, data)
    |> bytes_to_string()
  end

  if Code.ensure_loaded?(:crypto) and function_exported?(:crypto, :mac, 4) do
    def hmac_sha256(key, data), do: :crypto.mac(:hmac, :sha256, key, data)
  else
    def hmac_sha256(key, data), do: :crypto.hmac(:sha256, key, data)
  end

  def bytes_to_string(bytes) do
    Base.encode16(bytes, case: :lower)
  end

  def format_time(time) do
    formatted_time =
      time
      |> NaiveDateTime.to_iso8601()
      |> String.split(".")
      |> List.first()
      |> String.replace("-", "")
      |> String.replace(":", "")

    formatted_time <> "Z"
  end

  def format_date(date) do
    date
    |> NaiveDateTime.to_date()
    |> Date.to_iso8601()
    |> String.replace("-", "")
  end
end
