defmodule AWSAuth.Utils do
  @moduledoc false

  @doc """
  Filters out headers that should not be included in signing.
  AWS infrastructure may add trace headers that would break the signature.
  Additional headers can be excluded via the unsigned_headers option.
  """
  def filter_unsignable_headers(headers, unsigned_headers \\ []) do
    default_unsigned = ["x-amzn-trace-id"]
    all_unsigned = default_unsigned ++ Enum.map(unsigned_headers, &String.downcase/1)

    headers
    |> Enum.reject(fn {key, _value} ->
      String.downcase(key) in all_unsigned
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

  def build_canonical_request(
        http_method,
        path,
        params,
        headers,
        hashed_payload,
        uri_escape_path \\ true
      ) do
    validate_query_params(params)
    query_params = canonical_query_string(params)

    header_params =
      Enum.map(headers, fn {key, value} -> "#{String.downcase(key)}:#{String.trim(value)}" end)
      |> Enum.sort(&(&1 < &2))
      |> Enum.join("\n")

    signed_header_params = signed_headers(headers)

    hashed_payload =
      if hashed_payload == :unsigned,
        do: "UNSIGNED-PAYLOAD",
        else: hashed_payload

    encoded_path =
      if uri_escape_path do
        path
        |> String.split("/")
        |> Enum.map_join("/", &uri_encode/1)
      else
        path
      end

    "#{http_method}\n#{encoded_path}\n#{query_params}\n#{header_params}\n\n#{signed_header_params}\n#{hashed_payload}"
  end

  @doc """
  Builds the sorted, AWS-encoded query string used in a canonical request.

  Accepts any enumerable of key/value pairs and preserves duplicate keys.
  """
  def canonical_query_string(params) do
    params
    |> Enum.map(fn {key, value} -> {uri_encode(key), uri_encode(value)} end)
    |> Enum.sort()
    |> Enum.map_join("&", fn {key, value} -> "#{key}=#{value}" end)
  end

  @doc """
  URI-encodes a value according to the AWS Signature Version 4 rules.
  """
  def uri_encode(value) do
    value
    |> to_string()
    |> :binary.bin_to_list()
    |> Enum.map_join(fn byte ->
      if unreserved?(byte) do
        <<byte>>
      else
        "%" <> Base.encode16(<<byte>>)
      end
    end)
  end

  defp unreserved?(byte) do
    byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in [?-, ?., ?_, ?~]
  end

  def signed_headers(headers) do
    headers
    |> Enum.map(fn {key, _value} -> String.downcase(key) end)
    |> Enum.sort()
    |> Enum.join(";")
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

  @doc """
  Attempts to extract service and region from an AWS URL.
  Returns {service, region} or {nil, nil} if unable to parse.

  ## Examples

      iex> AWSAuth.Utils.parse_aws_url("https://s3.us-west-2.amazonaws.com/bucket/key")
      {"s3", "us-west-2"}

      iex> AWSAuth.Utils.parse_aws_url("https://bedrock-runtime.us-east-1.amazonaws.com/model/invoke")
      {"bedrock", "us-east-1"}

      iex> AWSAuth.Utils.parse_aws_url("https://example.com")
      {nil, nil}
  """
  def parse_aws_url(url) do
    uri = URI.parse(url)
    host = if is_binary(uri.host), do: String.downcase(uri.host, :ascii)
    parse_aws_host(host)
  end

  defp parse_aws_host(nil), do: {nil, nil}
  defp parse_aws_host("global.health.amazonaws.com"), do: {"health", "us-east-1"}
  defp parse_aws_host("global.health.amazonaws.com.cn"), do: {"health", "cn-northwest-1"}
  defp parse_aws_host("global.health.us-gov.amazonaws.com"), do: {"health", "us-gov-west-1"}

  defp parse_aws_host(host) do
    case aws_endpoint_parts(String.split(host, ".")) do
      {:ok, partition, endpoint_parts} -> parse_aws_endpoint(endpoint_parts, partition)
      :error -> {nil, nil}
    end
  end

  defp aws_endpoint_parts(parts) do
    case Enum.reverse(parts) do
      ["com", "amazonaws" | reversed_endpoint] ->
        {:ok, :aws, Enum.reverse(reversed_endpoint)}

      ["cn", "com", "amazonaws" | reversed_endpoint] ->
        {:ok, :aws_cn, Enum.reverse(reversed_endpoint)}

      ["aws", "api" | reversed_endpoint] ->
        {:ok, :aws, Enum.reverse(reversed_endpoint)}

      ["cn", "com", "amazonwebservices", "api" | reversed_endpoint] ->
        {:ok, :aws_cn, Enum.reverse(reversed_endpoint)}

      _other ->
        :error
    end
  end

  defp parse_aws_endpoint(parts, partition) do
    case last_index(parts, &s3_service_label?/1) do
      nil ->
        parse_legacy_s3_or_service(parts, partition)

      index ->
        service = parts |> Enum.at(index) |> s3_service_name()
        {service, s3_region(Enum.drop(parts, index + 1))}
    end
  end

  defp parse_legacy_s3_or_service(parts, partition) do
    case last_index(parts, &legacy_s3_label?/1) do
      nil -> parse_regional_service(parts, partition)
      index -> {"s3", legacy_s3_region(Enum.drop(parts, index))}
    end
  end

  defp parse_regional_service([service], partition) do
    normalized = strip_fips(service)
    signing_name = AWSAuth.SigningNames.get(normalized, normalized)
    {signing_name, global_region_for(signing_name, partition)}
  end

  defp parse_regional_service([service, region], partition) do
    normalized = strip_fips(service)
    signing_name = AWSAuth.SigningNames.get(normalized, normalized)
    {signing_name, normalize_region_label(region, signing_name, partition)}
  end

  defp parse_regional_service([_first, _second | _rest] = parts, partition) do
    {leading, [region]} = Enum.split(parts, -1)

    normalized_labels =
      leading
      |> Enum.reject(&(&1 in ["fips", "dualstack"]))
      |> Enum.map(&strip_fips/1)

    case normalized_labels do
      [single] ->
        signing_name = AWSAuth.SigningNames.get(single, single)
        {signing_name, normalize_region_label(region, signing_name, partition)}

      multiple ->
        prefix = Enum.join(multiple, ".")

        case AWSAuth.SigningNames.fetch(prefix) do
          {:ok, signing_name} ->
            {signing_name, normalize_region_label(region, signing_name, partition)}

          :error ->
            {nil, nil}
        end
    end
  end

  defp parse_regional_service(_parts, _partition), do: {nil, nil}

  defp strip_fips(label), do: String.trim_trailing(label, "-fips")

  defp normalize_region_label(region) do
    normalize_region_label(region, nil, :aws)
  end

  defp normalize_region_label(region, signing_name, partition)
       when region in ["global", "aws-global", "aws-cn-global"] do
    global_region_for(signing_name, partition)
  end

  defp normalize_region_label(region, _signing_name, _partition)
       when region in ["us-gov", "aws-us-gov-global"], do: "us-gov-west-1"

  defp normalize_region_label(region, _signing_name, _partition) do
    region
    |> String.trim_leading("fips-")
    |> String.trim_trailing("-fips")
  end

  defp global_region_for("codecatalyst", :aws), do: "aws-global"

  defp global_region_for(service, :aws)
       when service in ["networkmanager", "route53-recovery-control-config"], do: "us-west-2"

  defp global_region_for(service, :aws_cn) when service in ["iam", "support"], do: "cn-north-1"
  defp global_region_for(_signing_name, :aws_cn), do: "cn-northwest-1"
  defp global_region_for(_signing_name, _partition), do: "us-east-1"

  defp s3_service_label?(label), do: s3_service_name(label) != nil

  defp s3_service_name(label) do
    case strip_fips(label) do
      "s3" -> "s3"
      "s3-control" -> "s3"
      "s3-accesspoint" -> "s3"
      "s3-outposts" -> "s3-outposts"
      "s3-object-lambda" -> "s3-object-lambda"
      "s3express-control" -> "s3express"
      "s3express-" <> _az -> "s3express"
      _other -> nil
    end
  end

  defp s3_region([]), do: "us-east-1"
  defp s3_region([region]), do: normalize_region_label(region)
  defp s3_region(["dualstack", region]), do: normalize_region_label(region)
  defp s3_region(["fips", region]), do: normalize_region_label(region)
  defp s3_region(["fips", "dualstack", region]), do: normalize_region_label(region)
  defp s3_region(["dualstack", "fips", region]), do: normalize_region_label(region)
  defp s3_region(_parts), do: nil

  defp legacy_s3_region(["s3-" <> variant, region]) when variant in ["fips", "dualstack"],
    do: normalize_region_label(region)

  defp legacy_s3_region(["s3-" <> variant, "dualstack", region])
       when variant in ["fips", "dualstack"], do: normalize_region_label(region)

  defp legacy_s3_region(["s3-accelerate" | _rest]), do: nil
  defp legacy_s3_region(["s3-global" | _rest]), do: nil
  defp legacy_s3_region(["s3-external-1"]), do: "us-east-1"
  defp legacy_s3_region(["s3-" <> region]), do: normalize_region_label(region)
  defp legacy_s3_region(_parts), do: nil

  defp legacy_s3_label?(label)
       when label in ["s3-fips", "s3-dualstack", "s3-accelerate", "s3-global"], do: true

  defp legacy_s3_label?("s3-" <> region), do: Regex.match?(~r/^[a-z0-9-]+-\d$/, region)
  defp legacy_s3_label?(_label), do: false

  defp last_index(parts, predicate) do
    parts
    |> Enum.with_index()
    |> Enum.reduce(nil, fn {part, index}, found_index ->
      if predicate.(part), do: index, else: found_index
    end)
  end
end
