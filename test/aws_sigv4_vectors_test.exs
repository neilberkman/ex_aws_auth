defmodule AWSAuth.SigV4VectorsTest do
  use ExUnit.Case, async: true

  alias AWSAuth.Credentials

  @fixture_path Path.expand("fixtures/sigv4_vectors.json", __DIR__)
  @fixture @fixture_path |> File.read!() |> Jason.decode!()

  @shared @fixture["shared"]
  @creds %Credentials{
    access_key_id: @shared["access_key_id"],
    region: @shared["region"],
    secret_access_key: @shared["secret_access_key"]
  }
  @timestamp ~N[2025-01-01 00:00:00]

  describe "botocore reference signature vectors" do
    for vector <- @fixture["vectors"] do
      @vector vector

      test "vector #{vector["id"]} matches botocore (#{@fixture["botocore_version"]})" do
        creds = %{
          @creds
          | secret_access_key: @vector["secret_access_key"] || @shared["secret_access_key"],
            session_token: @vector["session_token"]
        }

        timestamp = parse_vector_timestamp(@vector["timestamp"])
        s3express_session = Map.get(@vector, "s3express_session", false)
        auth_scheme = if s3express_session, do: :s3express_session, else: :sigv4
        apply_checksum_header = Map.get(@vector, "apply_checksum_header", true)

        case @vector["kind"] do
          "header" ->
            headers =
              AWSAuth.sign_authorization_header(
                creds,
                @vector["method"],
                @vector["url"],
                @vector["service"],
                headers: @vector["headers"],
                payload: @vector["body"],
                region: @shared["region"],
                timestamp: timestamp,
                apply_checksum_header: apply_checksum_header,
                auth_scheme: auth_scheme,
                return_format: :map
              )

            assert extract_header_signature(headers["authorization"]) == @vector["signature"]

            if @vector["session_token"] do
              if s3express_session do
                assert headers["x-amz-s3session-token"] == @vector["session_token"]
                refute Map.has_key?(headers, "x-amz-security-token")
              else
                assert headers["x-amz-security-token"] == @vector["session_token"]
                refute Map.has_key?(headers, "x-amz-s3session-token")
              end
            end

          "presign" ->
            signed_url =
              AWSAuth.sign_url(
                creds,
                @vector["method"],
                @vector["url"],
                @vector["service"],
                headers: @vector["headers"],
                payload: @vector["body"],
                region: @shared["region"],
                timestamp: timestamp,
                expires_in: @vector["expires_in"],
                auth_scheme: auth_scheme
              )

            query = signed_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
            assert query["X-Amz-Signature"] == @vector["signature"]

            if @vector["session_token"] do
              if s3express_session do
                assert query["X-Amz-S3session-Token"] == @vector["session_token"]
                refute Map.has_key?(query, "X-Amz-Security-Token")
              else
                assert query["X-Amz-Security-Token"] == @vector["session_token"]
                refute Map.has_key?(query, "X-Amz-S3session-Token")
              end
            end
        end
      end
    end

    test "s3_space with uri_escape_path: true reproduces legacy double-encoded signature" do
      headers =
        AWSAuth.sign_authorization_header(
          @creds,
          "GET",
          "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b.txt",
          "s3",
          timestamp: @timestamp,
          uri_escape_path: true,
          return_format: :map
        )

      assert String.starts_with?(extract_header_signature(headers["authorization"]), "a1ef1980")
    end

    test "all S3-family services default to uri_escape_path: false" do
      for service <- ["s3", "s3-outposts", "s3-object-lambda", "s3express"] do
        assert AWSAuth.Utils.s3_family?(service)

        default_headers =
          AWSAuth.sign_authorization_header(
            @creds,
            "GET",
            "https://example.amazonaws.com/a%20b.txt",
            service,
            region: "us-east-1",
            timestamp: @timestamp,
            return_format: :map
          )

        explicit_false_headers =
          AWSAuth.sign_authorization_header(
            @creds,
            "GET",
            "https://example.amazonaws.com/a%20b.txt",
            service,
            region: "us-east-1",
            timestamp: @timestamp,
            uri_escape_path: false,
            return_format: :map
          )

        assert default_headers["authorization"] == explicit_false_headers["authorization"]
      end
    end

    test "strips stale security/s3session token headers and query params before applying the selected mode" do
      creds = %{@creds | session_token: "REAL_TOKEN"}
      url = "https://bucket--use1-az4--x-s3.s3express-use1-az4.us-east-1.amazonaws.com/k"

      for opt <- [auth_scheme: :s3express_session, s3express_session: true] do
        headers =
          AWSAuth.sign_authorization_header(
            creds,
            "GET",
            url,
            "s3express",
            [
              headers: %{"X-Amz-Security-Token" => "STALE"},
              timestamp: @timestamp,
              return_format: :map
            ] ++ [opt]
          )

        assert headers["x-amz-s3session-token"] == "REAL_TOKEN"
        refute Map.has_key?(headers, "x-amz-security-token")
        refute headers["authorization"] =~ "x-amz-security-token"

        presigned =
          AWSAuth.sign_url(
            creds,
            "GET",
            url <> "?X-Amz-Security-Token=STALE",
            "s3express",
            [headers: %{"X-Amz-Security-Token" => "STALE"}, timestamp: @timestamp] ++ [opt]
          )

        query = presigned |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
        assert query["X-Amz-S3session-Token"] == "REAL_TOKEN"
        assert query["X-Amz-SignedHeaders"] == "host"
        refute Map.has_key?(query, "X-Amz-Security-Token")
      end

      default_headers =
        AWSAuth.sign_authorization_header(
          creds,
          "GET",
          url,
          "s3express",
          headers: %{"x-amz-s3session-token" => "STALE"},
          timestamp: @timestamp,
          return_format: :map
        )

      assert default_headers["x-amz-security-token"] == "REAL_TOKEN"
      refute Map.has_key?(default_headers, "x-amz-s3session-token")
      refute default_headers["authorization"] =~ "x-amz-s3session-token"
    end
  end

  describe "canonical request fragments" do
    test "path_norm_api normalizes dot segments and empty segments for non-S3" do
      for {raw_path, expected} <- @fixture["fragments"]["path_norm_api"] do
        canonical =
          AWSAuth.Utils.build_canonical_request(
            "GET",
            raw_path,
            [],
            %{"host" => "h"},
            "hash",
            true
          )

        assert Enum.at(String.split(canonical, "\n"), 1) == expected
      end

      empty_canonical =
        AWSAuth.Utils.build_canonical_request("GET", "", [], %{"host" => "h"}, "hash", true)

      assert Enum.at(String.split(empty_canonical, "\n"), 1) == "/"
    end

    test "path_norm_s3 preserves S3 paths verbatim" do
      for {raw_path, expected} <- @fixture["fragments"]["path_norm_s3"] do
        canonical =
          AWSAuth.Utils.build_canonical_request(
            "GET",
            raw_path,
            [],
            %{"host" => "h"},
            "hash",
            false
          )

        assert Enum.at(String.split(canonical, "\n"), 1) == expected
      end
    end

    test "tab_header collapses all ASCII whitespace in canonical request and returned headers" do
      fragment = @fixture["fragments"]["tab_header"]

      canonical =
        AWSAuth.Utils.build_canonical_request(
          "PUT",
          "/k",
          [],
          %{"x-amz-meta-t" => fragment["input"]},
          "hash",
          false
        )

      assert canonical =~ fragment["canonical_line"]

      headers =
        AWSAuth.sign_authorization_header(
          @creds,
          "PUT",
          "https://b.s3.us-east-1.amazonaws.com/k",
          "s3",
          headers: %{"x-amz-meta-t" => fragment["input"]},
          timestamp: @timestamp,
          return_format: :map
        )

      assert headers["x-amz-meta-t"] == fragment["canonical_value"]
    end

    test "dup_header_list preserves repeated identical list values as a,a matching botocore" do
      fragment = @fixture["fragments"]["dup_header_list"]
      input_headers = Enum.map(fragment["input"], fn [k, v] -> {k, v} end)

      headers =
        AWSAuth.sign_authorization_header(
          @creds,
          "GET",
          "https://b.s3.us-east-1.amazonaws.com/k",
          "s3",
          headers: input_headers,
          timestamp: @timestamp,
          return_format: :map
        )

      assert headers["x-amz-meta-tag"] == fragment["canonical_value"]
    end

    test "query string canonicalization (D2) agrees on canonical wire queries and normalizes +, %7e, %2f, and UTF-8" do
      for {wire_query, expected_canonical} <- @fixture["fragments"]["query_canonical"] do
        decoded = Enum.to_list(URI.query_decoder(wire_query))
        assert AWSAuth.Utils.canonical_query_string(decoded) == expected_canonical
      end

      assert AWSAuth.Utils.canonical_query_string(URI.query_decoder("x=a+b")) == "x=a%20b"
      assert AWSAuth.Utils.canonical_query_string(URI.query_decoder("x=%7e")) == "x=~"
      assert AWSAuth.Utils.canonical_query_string(URI.query_decoder("x=%2f")) == "x=%2F"
      assert AWSAuth.Utils.canonical_query_string(URI.query_decoder("ሴ=bar")) == "%E1%88%B4=bar"

      assert AWSAuth.Utils.canonical_query_string(URI.query_decoder("prefix=a+b&k=x%2By")) ==
               "k=x%2By&prefix=a%20b"

      presigned =
        AWSAuth.sign_url(
          @creds,
          "GET",
          "https://examplebucket.s3.us-east-1.amazonaws.com/key?x=a+b&y=%7e&z=%2f",
          "s3",
          timestamp: @timestamp
        )

      assert presigned =~ "x=a%20b"
      assert presigned =~ "y=~"
      assert presigned =~ "z=%2F"

      signed_once =
        AWSAuth.sign_url(
          @creds,
          "GET",
          "https://examplebucket.s3.us-east-1.amazonaws.com/key",
          "s3",
          timestamp: @timestamp
        )

      signed_twice =
        AWSAuth.sign_url(
          @creds,
          "GET",
          signed_once,
          "s3",
          timestamp: @timestamp
        )

      signatures =
        signed_twice
        |> URI.parse()
        |> Map.fetch!(:query)
        |> URI.query_decoder()
        |> Enum.filter(fn {k, _v} -> k == "X-Amz-Signature" end)

      assert length(signatures) == 1
      assert signed_twice == signed_once
    end
  end

  defp parse_vector_timestamp(nil), do: @timestamp
  defp parse_vector_timestamp("20150830T123600Z"), do: ~N[2015-08-30 12:36:00]
  defp parse_vector_timestamp("20250101T000000Z"), do: @timestamp

  defp extract_header_signature("AWS4-HMAC-SHA256 " <> rest) do
    rest
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.find_value(fn
      "Signature=" <> sig -> sig
      _ -> nil
    end)
  end
end
