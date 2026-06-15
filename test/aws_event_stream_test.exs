defmodule AWSAuth.EventStreamTest do
  use ExUnit.Case, async: true

  alias AWSAuth.Credentials
  alias AWSAuth.EventStream

  doctest AWSAuth.EventStream

  # Reference vector taken verbatim from the aws-beam/aws_signature test suite
  # (src/aws_signature.erl, sign_v4_event_test/0). Matching this byte-for-byte
  # proves our native implementation produces canonical signatures.
  @secret_access_key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  @region "us-east-1"
  @service "transcribe"
  @datetime ~N[2023-07-31 11:36:12]
  @prior_signature "ce2704cf5f348fd66f179d5883162f223c30b3fb8213fb1bc097bf2ecd34b1b5"
  # EventStream-encoded {":date", @datetime, :timestamp} header
  @header_bytes <<5, 58, 100, 97, 116, 101, 8, 0, 0, 1, 137, 171, 187, 255, 224>>
  @expected_signature "29ef82c39850abdcc65f9d6046f3e437e385112b80b7f17b31ba33a7da3cc8af"

  defp creds do
    %Credentials{
      access_key_id: "AKIDEXAMPLE",
      region: @region,
      secret_access_key: @secret_access_key
    }
  end

  describe "sign_event/7" do
    test "matches the canonical aws_signature reference vector" do
      assert EventStream.sign_event(
               creds(),
               @service,
               @prior_signature,
               @header_bytes,
               "",
               @datetime
             ) == @expected_signature
    end

    test ":raw returns the 32-byte binary signature equal to the hex form" do
      raw =
        EventStream.sign_event(creds(), @service, @prior_signature, @header_bytes, "", @datetime,
          raw: true
        )

      assert byte_size(raw) == 32
      assert Base.encode16(raw, case: :lower) == @expected_signature
    end

    test ":region option overrides the credential region" do
      west = %{creds() | region: "us-east-1"}

      with_opt =
        EventStream.sign_event(west, @service, @prior_signature, @header_bytes, "", @datetime,
          region: "us-west-2"
        )

      without_opt =
        EventStream.sign_event(
          %{creds() | region: "us-west-2"},
          @service,
          @prior_signature,
          @header_bytes,
          "",
          @datetime
        )

      assert with_opt == without_opt
      refute with_opt == @expected_signature
    end

    test "different prior signatures produce different signatures (chaining)" do
      other =
        EventStream.sign_event(
          creds(),
          @service,
          String.duplicate("a", 64),
          @header_bytes,
          "",
          @datetime
        )

      refute other == @expected_signature
    end
  end

  describe "encode_timestamp_header/2" do
    test "encodes the :date header to the canonical bytes" do
      assert EventStream.encode_timestamp_header(":date", @datetime) == @header_bytes
    end

    test "DateTime and equivalent UTC NaiveDateTime encode identically" do
      dt = DateTime.from_naive!(@datetime, "Etc/UTC")
      assert EventStream.encode_timestamp_header(":date", dt) == @header_bytes
    end
  end

  describe "encode_byte_array_header/2" do
    test "prefixes a 16-bit big-endian length and uses value type 6" do
      value = <<1, 2, 3, 4>>

      assert EventStream.encode_byte_array_header(":chunk-signature", value) ==
               <<16, ":chunk-signature", 6, 0, 4, 1, 2, 3, 4>>
    end
  end

  describe "encode_message/2" do
    test "frames headers + payload with valid prelude and message CRCs" do
      headers = EventStream.encode_timestamp_header(":date", @datetime)
      payload = "hello"
      frame = EventStream.encode_message(headers, payload)

      headers_length = byte_size(headers)
      total_length = 16 + headers_length + byte_size(payload)

      assert byte_size(frame) == total_length

      <<prelude::binary-size(8), prelude_crc::big-32, rest::binary>> = frame
      assert prelude == <<total_length::big-32, headers_length::big-32>>
      assert prelude_crc == :erlang.crc32(prelude)

      body = binary_part(rest, 0, byte_size(rest) - 4)
      <<message_crc::big-32>> = binary_part(rest, byte_size(rest) - 4, 4)
      assert body == headers <> payload
      assert message_crc == :erlang.crc32(<<prelude::binary, prelude_crc::big-32, body::binary>>)
    end
  end

  describe "sign_message/6" do
    test "returns a wire frame and the hex signature for chaining" do
      {frame, signature} =
        EventStream.sign_message(creds(), @service, @prior_signature, "", @datetime)

      # With an empty payload and the :date header, the signature must match
      # the reference vector (same inputs as sign_event/7 above).
      assert signature == @expected_signature

      # The frame must embed the :date and :chunk-signature headers.
      assert frame =~ ":date"
      assert frame =~ ":chunk-signature"

      # The frame is internally consistent (CRCs validate).
      <<prelude::binary-size(8), prelude_crc::big-32, _::binary>> = frame
      assert prelude_crc == :erlang.crc32(prelude)
    end

    test "feeds its signature forward to the next event" do
      {_f1, sig1} =
        EventStream.sign_message(creds(), @service, @prior_signature, "chunk-1", @datetime)

      {_f2, sig2} = EventStream.sign_message(creds(), @service, sig1, "chunk-2", @datetime)

      refute sig1 == sig2
      assert String.length(sig1) == 64
      assert String.length(sig2) == 64
    end
  end
end
