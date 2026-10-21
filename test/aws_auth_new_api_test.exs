defmodule AWSAuth.NewAPITest do
  use ExUnit.Case, async: true

  alias AWSAuth.Credentials

  setup do
    creds = %Credentials{
      access_key_id: "AKIAIOSFODNN7EXAMPLE",
      region: "us-east-1",
      secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      session_token: "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
    }

    {:ok, creds: creds}
  end

  describe "sign_url/5 with Credentials struct" do
    test "signs URL with credentials struct", %{creds: creds} do
      url = "https://s3.amazonaws.com/mybucket/mykey"

      signed_url = AWSAuth.sign_url(creds, "GET", url, "s3")

      assert is_binary(signed_url)
      assert String.contains?(signed_url, "X-Amz-Algorithm=AWS4-HMAC-SHA256")
      assert String.contains?(signed_url, "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE")

      assert String.contains?(
               signed_url,
               "X-Amz-Security-Token=FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
             )
    end

    test "uses region from credentials", %{creds: creds} do
      url = "https://s3.amazonaws.com/mybucket/mykey"

      signed_url = AWSAuth.sign_url(creds, "GET", url, "s3")

      assert String.contains?(signed_url, "us-east-1")
    end

    test "allows region override", %{creds: creds} do
      url = "https://s3.amazonaws.com/mybucket/mykey"

      signed_url = AWSAuth.sign_url(creds, "GET", url, "s3", region: "eu-west-1")

      assert String.contains?(signed_url, "eu-west-1")
      refute String.contains?(signed_url, "us-east-1")
    end

    test "accepts optional headers", %{creds: creds} do
      url = "https://s3.amazonaws.com/mybucket/mykey"
      headers = %{"x-amz-meta-foo" => "bar"}

      signed_url = AWSAuth.sign_url(creds, "GET", url, "s3", headers: headers)

      assert is_binary(signed_url)
      assert String.contains?(signed_url, "X-Amz-Algorithm=AWS4-HMAC-SHA256")
    end

    test "accepts payload", %{creds: creds} do
      url = "https://s3.amazonaws.com/mybucket/mykey"
      payload = Jason.encode!(%{test: "data"})

      signed_url = AWSAuth.sign_url(creds, "POST", url, "s3", payload: payload)

      assert is_binary(signed_url)
      assert String.contains?(signed_url, "X-Amz-Algorithm=AWS4-HMAC-SHA256")
    end

    test "works with credentials without session token" do
      creds = %Credentials{
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        region: "us-east-1",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      }

      url = "https://s3.amazonaws.com/mybucket/mykey"
      signed_url = AWSAuth.sign_url(creds, "GET", url, "s3")

      assert is_binary(signed_url)
      refute String.contains?(signed_url, "X-Amz-Security-Token")
    end

    test "rejects expiration times outside the AWS range", %{creds: creds} do
      url = "https://s3.amazonaws.com/mybucket/mykey"

      for expires_in <- [0, 604_801, "not-an-integer", 1.5] do
        assert_raise ArgumentError, ~r/:expires_in must be an integer between 1 and 604800/, fn ->
          AWSAuth.sign_url(creds, "GET", url, "s3", expires_in: expires_in)
        end
      end
    end

    test "accepts an integer expiration from configuration", %{creds: creds} do
      signed_url =
        AWSAuth.sign_url(
          creds,
          "GET",
          "https://s3.amazonaws.com/mybucket/mykey",
          "s3",
          expires_in: "3600"
        )

      assert URI.decode_query(URI.parse(signed_url).query)["X-Amz-Expires"] == "3600"
    end

    test "preserves duplicate query parameters", %{creds: creds} do
      signed_url =
        AWSAuth.sign_url(
          creds,
          "GET",
          "https://s3.amazonaws.com/mybucket/mykey?partNumber=2&partNumber=1",
          "s3"
        )

      part_numbers =
        signed_url
        |> URI.parse()
        |> Map.fetch!(:query)
        |> URI.query_decoder()
        |> Enum.filter(fn {key, _value} -> key == "partNumber" end)

      assert part_numbers == [{"partNumber", "1"}, {"partNumber", "2"}]
    end

    test "signs an endpoint URL with no path", %{creds: creds} do
      signed_url =
        AWSAuth.sign_url(
          creds,
          "GET",
          "https://sts.us-east-1.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
          "sts"
        )

      assert URI.parse(signed_url).path == "/"
    end

    test "lowercases and sorts signed headers", %{creds: creds} do
      signed_url =
        AWSAuth.sign_url(
          creds,
          "GET",
          "https://s3.amazonaws.com/mybucket/mykey",
          "s3",
          headers: %{"X-Amz-Acl" => "public-read"}
        )

      assert URI.decode_query(URI.parse(signed_url).query)["X-Amz-SignedHeaders"] ==
               "host;x-amz-acl"
    end

    test "raises a clear error when service detection fails", %{creds: creds} do
      assert_raise ArgumentError, ~r/could not detect an AWS service/, fn ->
        AWSAuth.sign_url(creds, "GET", "https://example.com/resource", nil)
      end
    end
  end

  describe "sign_authorization_header/5 with Credentials struct" do
    test "signs headers with credentials struct", %{creds: creds} do
      url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/my-model/invoke"
      body = Jason.encode!(%{prompt: "test"})

      headers =
        AWSAuth.sign_authorization_header(creds, "POST", url, "bedrock",
          headers: %{},
          payload: body
        )

      assert is_list(headers)
      {_, auth_header} = List.keyfind(headers, "authorization", 0)
      assert String.contains?(auth_header, "AWS4-HMAC-SHA256")
      assert String.contains?(auth_header, "AKIAIOSFODNN7EXAMPLE")

      # Should include session token header
      assert {"x-amz-security-token", "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"} in headers
    end

    test "returns list format by default", %{creds: creds} do
      url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/my-model/invoke"

      headers = AWSAuth.sign_authorization_header(creds, "POST", url, "bedrock")

      assert is_list(headers)
      assert Enum.all?(headers, fn {k, v} -> is_binary(k) and is_binary(v) end)
    end

    test "returns map format when requested", %{creds: creds} do
      url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/my-model/invoke"

      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "POST",
          url,
          "bedrock",
          return_format: :map
        )

      assert is_map(headers)
      assert Map.has_key?(headers, "authorization")
      assert Map.has_key?(headers, "x-amz-date")
      assert is_binary(headers["authorization"])
    end

    test "returns Req format when requested", %{creds: creds} do
      url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/my-model/invoke"

      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "POST",
          url,
          "bedrock",
          return_format: :req
        )

      assert is_map(headers)
      assert Map.has_key?(headers, "authorization")
      # Req format wraps values in lists
      assert is_list(headers["authorization"])
      assert is_list(headers["x-amz-date"])
    end

    test "uses region from credentials", %{creds: creds} do
      url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/my-model/invoke"

      headers = AWSAuth.sign_authorization_header(creds, "POST", url, "bedrock")

      {_, auth_header} = List.keyfind(headers, "authorization", 0)
      # Check that the credential scope includes us-east-1
      assert String.contains?(auth_header, "us-east-1/bedrock/aws4_request")
    end

    test "allows region override", %{creds: creds} do
      url = "https://bedrock-runtime.eu-west-1.amazonaws.com/model/my-model/invoke"

      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "POST",
          url,
          "bedrock",
          region: "eu-west-1"
        )

      {_, auth_header} = List.keyfind(headers, "authorization", 0)
      assert String.contains?(auth_header, "eu-west-1/bedrock/aws4_request")
    end

    test "works with credentials without session token" do
      creds = %Credentials{
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        region: "us-east-1",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      }

      url = "https://s3.amazonaws.com/mybucket/mykey"

      headers = AWSAuth.sign_authorization_header(creds, "GET", url, "s3")

      assert is_list(headers)
      refute List.keymember?(headers, "x-amz-security-token", 0)
    end

    test "merges provided headers", %{creds: creds} do
      url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/my-model/invoke"
      request_headers = %{"content-type" => "application/json", "x-custom" => "value"}

      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "POST",
          url,
          "bedrock",
          headers: request_headers
        )

      # Signing should preserve and include custom headers in signature
      assert is_list(headers)
    end
  end

  describe "backward compatibility" do
    test "old 10-parameter sign_url still works" do
      signed_url =
        AWSAuth.sign_url(
          "AKIAIOSFODNN7EXAMPLE",
          "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          "GET",
          "https://s3.amazonaws.com/mybucket/mykey",
          "us-east-1",
          "s3",
          %{},
          NaiveDateTime.utc_now(),
          "",
          "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
        )

      assert is_binary(signed_url)
      assert String.contains?(signed_url, "X-Amz-Algorithm=AWS4-HMAC-SHA256")
    end

    test "old 10-parameter sign_authorization_header still works" do
      headers =
        AWSAuth.sign_authorization_header(
          "AKIAIOSFODNN7EXAMPLE",
          "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          "POST",
          "https://bedrock-runtime.us-east-1.amazonaws.com/model/my-model/invoke",
          "us-east-1",
          "bedrock",
          %{},
          "",
          NaiveDateTime.utc_now(),
          "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
        )

      assert is_list(headers)
      assert Enum.all?(headers, fn {k, v} -> is_binary(k) and is_binary(v) end)
    end

    test "old APIs return list format (not affected by new return_format option)" do
      # Verify the old API signature doesn't accidentally use return_format
      headers =
        AWSAuth.sign_authorization_header(
          "AKIAIOSFODNN7EXAMPLE",
          "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          "POST",
          "https://s3.amazonaws.com/mybucket/mykey",
          "us-east-1",
          "s3",
          %{},
          "",
          NaiveDateTime.utc_now(),
          nil
        )

      # Should still return list of tuples
      assert is_list(headers)
      assert Enum.all?(headers, fn {k, v} -> is_binary(k) and is_binary(v) end)
    end
  end

  describe "payload: :streaming_events (event-stream seed)" do
    test "sets x-amz-content-sha256 to the streaming-events sentinel and signs it" do
      creds = %Credentials{
        access_key_id: "AKIDEXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region: "us-east-1"
      }

      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "POST",
          "https://bedrock-runtime.us-east-1.amazonaws.com/model/m/invoke-with-bidirectional-stream",
          "bedrock",
          headers: %{"host" => "bedrock-runtime.us-east-1.amazonaws.com"},
          payload: :streaming_events,
          timestamp: ~N[2026-06-15 12:00:00],
          return_format: :map
        )

      assert headers["x-amz-content-sha256"] == "STREAMING-AWS4-HMAC-SHA256-EVENTS"
      assert headers["authorization"] =~ "SignedHeaders=host;x-amz-content-sha256;x-amz-date"
      assert headers["authorization"] =~ ~r/Signature=[0-9a-f]{64}/
    end
  end

  describe "header normalization, collisions, host override, and unsigned headers" do
    test "capitalized Host header yields a single lowercase host and SignedHeaders=host;...", %{
      creds: creds
    } do
      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "GET",
          "https://s3.amazonaws.com/",
          "s3",
          headers: %{"Host" => "s3.amazonaws.com", "Content-Type" => "text/plain"},
          timestamp: ~N[2025-01-01 00:00:00]
        )

      host_entries = Enum.filter(headers, fn {k, _v} -> String.downcase(k) == "host" end)
      assert host_entries == [{"host", "s3.amazonaws.com"}]
      assert {"content-type", "text/plain"} in headers

      {_, auth} = List.keyfind(headers, "authorization", 0)

      assert auth =~
               "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token"

      refute auth =~ "host;host"
    end

    test "explicit host header is preserved over URL host", %{creds: creds} do
      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "GET",
          "http://localhost:4566/bucket/key",
          "s3",
          headers: %{"host" => "custom"},
          timestamp: ~N[2025-01-01 00:00:00],
          return_format: :map
        )

      assert headers["host"] == "custom"
    end

    test "case-insensitive map header collision with different values raises ArgumentError", %{
      creds: creds
    } do
      assert_raise ArgumentError, ~r/x-amz-meta-a/, fn ->
        AWSAuth.sign_authorization_header(
          creds,
          "GET",
          "https://s3.amazonaws.com/bucket/key",
          "s3",
          headers: %{"X-Amz-Meta-A" => "1", "x-amz-meta-a" => "2"}
        )
      end
    end

    test "case-insensitive map header collision with identical trimmed values deduplicates", %{
      creds: creds
    } do
      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "GET",
          "https://s3.amazonaws.com/bucket/key",
          "s3",
          headers: %{"X-Amz-Meta-A" => "1", "x-amz-meta-a" => " 1 "},
          return_format: :map
        )

      assert headers["x-amz-meta-a"] == "1"
    end

    test "list input with repeated header names comma-joins in order", %{creds: creds} do
      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "GET",
          "https://s3.amazonaws.com/bucket/key",
          "s3",
          headers: [{"x-amz-meta-tag", "a"}, {"x-amz-meta-tag", "b"}],
          return_format: :map
        )

      assert headers["x-amz-meta-tag"] == "a,b"
      assert headers["authorization"] =~ "x-amz-meta-tag"
    end

    test "default and custom unsigned_headers exclude headers from SignedHeaders but keep them in returned list",
         %{
           creds: creds
         } do
      headers =
        AWSAuth.sign_authorization_header(
          creds,
          "GET",
          "https://s3.amazonaws.com/bucket/key",
          "s3",
          headers: %{
            "User-Agent" => "my-agent",
            "Expect" => "100-continue",
            "X-Custom-Unsigned" => "skip-me",
            "x-amz-acl" => "public-read"
          },
          unsigned_headers: ["x-custom-unsigned"]
        )

      assert {"user-agent", "my-agent"} in headers
      assert {"expect", "100-continue"} in headers
      assert {"x-custom-unsigned", "skip-me"} in headers
      {_, auth} = List.keyfind(headers, "authorization", 0)
      refute auth =~ "user-agent"
      refute auth =~ "expect"
      refute auth =~ "x-custom-unsigned"
      assert auth =~ "x-amz-acl"
    end

    test "sign_url honors unsigned_headers", %{creds: creds} do
      signed_url =
        AWSAuth.sign_url(
          creds,
          "PUT",
          "https://s3.amazonaws.com/bucket/key",
          "s3",
          headers: %{"x-amz-acl" => "public-read", "x-amz-meta-keep" => "1"},
          unsigned_headers: ["x-amz-acl"]
        )

      signed_headers =
        signed_url
        |> URI.parse()
        |> Map.fetch!(:query)
        |> URI.decode_query()
        |> Map.fetch!("X-Amz-SignedHeaders")

      assert signed_headers == "host;x-amz-meta-keep"
    end
  end

  describe "region resolution precedence (D1)" do
    test "URL region beats credentials.region; explicit region beats URL; credentials.region covers non-regional hosts" do
      creds_east = %Credentials{
        access_key_id: "AKIDEXAMPLE",
        region: "us-east-1",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      }

      creds_west = %{creds_east | region: "us-west-2"}

      # URL region (eu-west-1) beats credentials.region (us-east-1)
      headers =
        AWSAuth.sign_authorization_header(
          creds_east,
          "GET",
          "https://b.s3.eu-west-1.amazonaws.com/k",
          "s3",
          return_format: :map
        )

      assert headers["authorization"] =~ "/eu-west-1/s3/aws4_request"

      # Explicit :region beats URL region
      override_headers =
        AWSAuth.sign_authorization_header(
          creds_east,
          "GET",
          "https://b.s3.eu-west-1.amazonaws.com/k",
          "s3",
          region: "ap-northeast-1",
          return_format: :map
        )

      assert override_headers["authorization"] =~ "/ap-northeast-1/s3/aws4_request"

      # Global AWS endpoint resolves us-east-1
      assert AWSAuth.resolve_region(nil, "https://iam.amazonaws.com", creds_west) == "us-east-1"

      # Non-AWS host falls back to credentials.region
      assert AWSAuth.resolve_region(nil, "http://localhost:4566/bucket/key", creds_west) ==
               "us-west-2"
    end
  end
end
