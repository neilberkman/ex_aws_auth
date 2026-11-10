defmodule AWSAuth.EventStream do
  @moduledoc """
  AWS Signature Version 4 signing for event stream messages.

  Some AWS APIs accept a stream of events from the client over a single
  connection (for example Amazon Transcribe streaming and Bedrock
  bidirectional streaming). Each event is individually signed, and the
  signatures form a chain: the first event is signed using the seed
  signature from the initial HTTP request's `Authorization` header, and each
  subsequent event is signed using the signature of the event before it.

  The signature for an event is computed as:

      string_to_sign =
        "AWS4-HMAC-SHA256-PAYLOAD" <> "\\n" <>
        <amz_date>                 <> "\\n" <>   # YYYYMMDDTHHMMSSZ
        <credential_scope>         <> "\\n" <>   # YYYYMMDD/region/service/aws4_request
        <prior_signature>          <> "\\n" <>   # hex
        sha256_hex(<header_bytes>) <> "\\n" <>
        sha256_hex(<payload>)

      signature = hmac_sha256(signing_key, string_to_sign)

  ## High-level usage

  `sign_message/6` does the whole thing — encode the `:date` header, sign,
  and frame a wire-ready event stream message. Chain the returned signature
  into the next call:

      seed = "..." # signature from the initial request's Authorization header
      creds = AWSAuth.Credentials.from_env() |> Map.put(:region, "us-east-1")

      {frame1, sig1} =
        AWSAuth.EventStream.sign_message(creds, "transcribe", seed, payload1, time1)

      {frame2, sig2} =
        AWSAuth.EventStream.sign_message(creds, "transcribe", sig1, payload2, time2)

  ## Low-level usage

  `sign_event/7` mirrors the canonical algorithm exactly (and matches the
  `aws_signature` Erlang library's `sign_v4_event/7`) when you want to control
  the encoded header bytes yourself.
  """

  alias AWSAuth.Credentials
  alias AWSAuth.Utils

  # Event stream header value type identifiers.
  # https://docs.aws.amazon.com/transcribe/latest/dg/streaming-setting-up.html
  @type_byte_array 6
  @type_string 7
  @type_timestamp 8

  # Limits from the event stream encoding: the name length is one byte and a
  # header value is at most 32767 bytes.
  @max_header_name_bytes 255
  @max_header_value_bytes 32_767

  # Per-message limits enforced by AWS and by botocore's decoder.
  @max_headers_bytes 128 * 1024
  @max_payload_bytes 24 * 1024 * 1024

  @doc """
  Signs a single event and returns the chunk signature as a lowercase hex string.

  This is the low-level entry point. `header_bytes` must be the event's headers
  already serialized in the AWS event stream binary format (typically just the
  `:date` header — see `encode_timestamp_header/2`), and `payload` is the raw
  event payload.

  Options:

    * `:region` - overrides the region from `credentials`
    * `:raw` - when `true`, returns the raw 32-byte signature instead of hex

  ## Example

      iex> creds = %AWSAuth.Credentials{
      ...>   access_key_id: "AKIDEXAMPLE",
      ...>   secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      ...>   region: "us-east-1"
      ...> }
      iex> header_bytes = <<5, 58, 100, 97, 116, 101, 8, 0, 0, 1, 137, 171, 187, 255, 224>>
      iex> AWSAuth.EventStream.sign_event(
      ...>   creds,
      ...>   "transcribe",
      ...>   "ce2704cf5f348fd66f179d5883162f223c30b3fb8213fb1bc097bf2ecd34b1b5",
      ...>   header_bytes,
      ...>   "",
      ...>   ~N[2023-07-31 11:36:12]
      ...> )
      "29ef82c39850abdcc65f9d6046f3e437e385112b80b7f17b31ba33a7da3cc8af"
  """
  def sign_event(
        %Credentials{} = credentials,
        service,
        prior_signature,
        header_bytes,
        payload,
        request_time,
        opts \\ []
      )
      when is_binary(prior_signature) and is_binary(header_bytes) do
    Utils.validate_secret_key!(credentials.secret_access_key)
    region = (opts[:region] || credentials.region || "us-east-1") |> String.downcase()
    service = to_string(service)

    naive = to_naive(request_time)
    amz_date = Utils.format_time(naive)
    date = Utils.format_date(naive)
    scope = "#{date}/#{region}/#{service}/aws4_request"

    string_to_sign =
      Enum.join(
        [
          "AWS4-HMAC-SHA256-PAYLOAD",
          amz_date,
          scope,
          prior_signature,
          Utils.hash_sha256(header_bytes),
          Utils.hash_sha256(payload)
        ],
        "\n"
      )

    signature =
      credentials.secret_access_key
      |> Utils.build_signing_key(date, region, service)
      |> Utils.hmac_sha256(string_to_sign)

    if opts[:raw], do: signature, else: Utils.bytes_to_string(signature)
  end

  @doc """
  Signs an event and frames it as a wire-ready event stream message.

  Encodes the `:date` header from `request_time`, signs the message (using the
  encoded `:date` header as the signed headers and `payload` as the body),
  then builds the full event stream frame containing the `:date` and
  `:chunk-signature` headers followed by `payload`.

  Returns `{frame, signature_hex}`. Pass `signature_hex` as the
  `prior_signature` for the next event in the stream.

  Accepts the same options as `sign_event/7` (except `:raw`).
  """
  def sign_message(
        %Credentials{} = credentials,
        service,
        prior_signature,
        payload,
        request_time,
        opts \\ []
      ) do
    date_header = encode_timestamp_header(":date", request_time)

    raw_signature =
      sign_event(
        credentials,
        service,
        prior_signature,
        date_header,
        payload,
        request_time,
        Keyword.put(opts, :raw, true)
      )

    headers = date_header <> encode_byte_array_header(":chunk-signature", raw_signature)
    {encode_message(headers, payload), Utils.bytes_to_string(raw_signature)}
  end

  @doc """
  Encodes a timestamp header (value type 8) into the AWS event stream binary
  format. The value is the milliseconds since the Unix epoch.

  `request_time` may be a `NaiveDateTime` (interpreted as UTC) or a `DateTime`.
  """
  def encode_timestamp_header(name, request_time) do
    millis = to_unix_ms(request_time)
    encode_header(name, @type_timestamp, <<millis::big-signed-64>>)
  end

  @doc """
  Encodes a byte-array header (value type 6) into the AWS event stream binary
  format. The value is length-prefixed with a 16-bit big-endian length.

  Raises `ArgumentError` if `name` is longer than 255 bytes or `value` is longer
  than 32767 bytes.
  """
  def encode_byte_array_header(name, value) when is_binary(value) do
    validate_header_value_size!(name, value)
    encode_header(name, @type_byte_array, <<byte_size(value)::big-16, value::binary>>)
  end

  @doc """
  Encodes a string header (value type 7) into the AWS event stream binary
  format. The value is length-prefixed with a 16-bit big-endian length.

  Used for application message headers such as `:content-type`, `:event-type`,
  and `:message-type` on the events some services expect (e.g. Bedrock
  bidirectional streaming input chunks).

  Raises `ArgumentError` if `name` is longer than 255 bytes or `value` is longer
  than 32767 bytes.
  """
  def encode_string_header(name, value) when is_binary(value) do
    if !String.valid?(value) do
      raise ArgumentError, "event stream string header #{inspect(name)} value must be valid UTF-8"
    end

    validate_header_value_size!(name, value)
    encode_header(name, @type_string, <<byte_size(value)::big-16, value::binary>>)
  end

  @doc """
  Frames serialized `headers` and a `payload` into a complete event stream
  message, including the prelude, prelude CRC, and message CRC.

  ## Wire format

      [total length      :: big-32]
      [headers length    :: big-32]
      [prelude CRC32      :: big-32]   # crc32 of the 8 prelude bytes above
      [headers bytes]
      [payload bytes]
      [message CRC32      :: big-32]   # crc32 of everything before it

  Raises `ArgumentError` if `headers` is over 128 KiB or `payload` is over
  24 MiB, the per-message limits AWS enforces.
  """
  def encode_message(headers, payload) when is_binary(headers) and is_binary(payload) do
    headers_length = byte_size(headers)

    if headers_length > @max_headers_bytes do
      raise ArgumentError,
            "event stream headers are #{headers_length} bytes; the maximum is #{@max_headers_bytes}"
    end

    if byte_size(payload) > @max_payload_bytes do
      raise ArgumentError,
            "event stream payload is #{byte_size(payload)} bytes; the maximum is #{@max_payload_bytes}"
    end

    total_length = 16 + headers_length + byte_size(payload)

    prelude = <<total_length::big-32, headers_length::big-32>>
    prelude_crc = :erlang.crc32(prelude)

    message_without_crc = prelude <> <<prelude_crc::big-32>> <> headers <> payload
    message_crc = :erlang.crc32(message_without_crc)

    message_without_crc <> <<message_crc::big-32>>
  end

  defp encode_header(name, type, value) do
    if !(is_binary(name) and String.valid?(name)) do
      raise ArgumentError,
            "event stream header name must be a UTF-8 string, got: #{inspect(name)}"
    end

    if byte_size(name) == 0 or byte_size(name) > @max_header_name_bytes do
      raise ArgumentError,
            "event stream header name must be 1..#{@max_header_name_bytes} bytes, got #{byte_size(name)}"
    end

    <<byte_size(name)::8, name::binary, type::8, value::binary>>
  end

  defp validate_header_value_size!(name, value) do
    if byte_size(value) > @max_header_value_bytes do
      raise ArgumentError,
            "event stream header #{inspect(name)} value is #{byte_size(value)} bytes; the maximum is #{@max_header_value_bytes}"
    end
  end

  defp to_naive(%NaiveDateTime{} = t), do: t

  # Convert through the Unix instant so a non-UTC `DateTime` signs with the same
  # UTC wall time that `to_unix_ms/1` puts in the `:date` header.
  defp to_naive(%DateTime{} = t) do
    t
    |> DateTime.to_unix(:microsecond)
    |> DateTime.from_unix!(:microsecond)
    |> DateTime.to_naive()
  end

  defp to_unix_ms(%DateTime{} = t), do: DateTime.to_unix(t, :millisecond)

  defp to_unix_ms(%NaiveDateTime{} = t) do
    t |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix(:millisecond)
  end
end
