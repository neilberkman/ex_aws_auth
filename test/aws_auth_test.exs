defmodule AWSAuthTest do
  use ExUnit.Case

  @time ~N[2013-05-24 01:23:45]

  test "url signing" do
    signed_request =
      AWSAuth.sign_url(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "GET",
        "https://examplebucket.s3.amazonaws.com/test.txt",
        "us-east-1",
        "s3",
        Map.new(),
        @time
      )
      |> URI.parse()

    assert signed_request.host == "examplebucket.s3.amazonaws.com"
    assert signed_request.scheme == "https"
    assert signed_request.path == "/test.txt"

    expected_query_parts = [
      {"X-Amz-Algorithm", "AWS4-HMAC-SHA256"},
      {"X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"},
      {"X-Amz-Date", "20130524T012345Z"},
      {"X-Amz-Expires", "86400"},
      {"X-Amz-Signature", "e78f6cd3458a7e2b49a5db198a304414581bc823a3d8160d6b1178bfd93c7026"},
      {"X-Amz-SignedHeaders", "host"}
    ]

    query_parts = URI.query_decoder(signed_request.query) |> Enum.to_list()
    assert query_parts == expected_query_parts
  end

  test "sign_authorization_header PUT" do
    headers =
      Map.new()
      |> Map.put("Date", "Fri, 24 May 2013 00:00:00 GMT")
      |> Map.put("x-amz-storage-class", "REDUCED_REDUNDANCY")
      |> Map.put("x-amz-date", "20130524T000000Z")

    signed_request =
      AWSAuth.sign_authorization_header(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "PUT",
        "https://examplebucket.s3.amazonaws.com/test$file.text",
        "us-east-1",
        "s3",
        headers,
        "Welcome to Amazon S3.",
        @time
      )

    {"authorization", "AWS4-HMAC-SHA256 " <> request_parts} =
      signed_request |> List.keyfind("authorization", 0)

    request_parts = String.split(request_parts, ",") |> Enum.map(&String.split(&1, "="))

    assert request_parts == [
             ["Credential", "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"],
             ["SignedHeaders", "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class"],
             ["Signature", "cb26a806062d11d1ba2debc79cfebbe2bae32c39f039cbb4f7df09e9450c9caa"]
           ]
  end

  test "sign_query_parameters_request_with_multiple_headers" do
    headers =
      Map.new()
      |> Map.put("x-amz-acl", "public-read")

    signed_request =
      AWSAuth.sign_url(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "PUT",
        "https://examplebucket.s3.amazonaws.com/test.txt",
        "us-east-1",
        "s3",
        headers,
        @time
      )
      |> URI.parse()

    assert signed_request.host == "examplebucket.s3.amazonaws.com"
    assert signed_request.scheme == "https"
    assert signed_request.path == "/test.txt"

    expected_query_parts = [
      {"X-Amz-Algorithm", "AWS4-HMAC-SHA256"},
      {"X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"},
      {"X-Amz-Date", "20130524T012345Z"},
      {"X-Amz-Expires", "86400"},
      {"X-Amz-Signature", "486cf3cae7cf411a757b859139da22000288900fa78c18377fd57f243bbc7d01"},
      {"X-Amz-SignedHeaders", "host;x-amz-acl"}
    ]

    query_parts = URI.query_decoder(signed_request.query) |> Enum.to_list()
    assert query_parts == expected_query_parts
  end

  test "sign_url with session token" do
    session_token = "FwoGZXIvYXdzEBYaDHhB..."

    signed_request =
      AWSAuth.sign_url(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "GET",
        "https://examplebucket.s3.amazonaws.com/test.txt",
        "us-east-1",
        "s3",
        Map.new(),
        @time,
        "",
        session_token
      )
      |> URI.parse()

    query_parts = URI.query_decoder(signed_request.query) |> Map.new()

    # Should include the session token in query params
    assert query_parts["X-Amz-Security-Token"] == session_token

    # Should still have all the standard signing components
    assert query_parts["X-Amz-Algorithm"] == "AWS4-HMAC-SHA256"
    assert query_parts["X-Amz-Credential"]
    assert query_parts["X-Amz-Date"]
    assert query_parts["X-Amz-Signature"]
  end

  test "sign_authorization_header with session token" do
    session_token = "FwoGZXIvYXdzEBYaDHhB..."

    headers =
      Map.new()
      |> Map.put("Date", "Fri, 24 May 2013 00:00:00 GMT")

    signed_request =
      AWSAuth.sign_authorization_header(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "GET",
        "https://examplebucket.s3.amazonaws.com/test.txt",
        "us-east-1",
        "s3",
        headers,
        "",
        @time,
        session_token
      )

    # Should include the session token header
    assert List.keyfind(signed_request, "x-amz-security-token", 0) ==
             {"x-amz-security-token", session_token}

    # Should still have the authorization header
    assert List.keyfind(signed_request, "authorization", 0)

    # Session token should be included in signed headers
    {"authorization", auth_value} = List.keyfind(signed_request, "authorization", 0)
    assert auth_value =~ "x-amz-security-token"
  end

  test "sign_authorization_header filters trace headers" do
    headers =
      Map.new()
      |> Map.put("Date", "Fri, 24 May 2013 00:00:00 GMT")
      |> Map.put("x-amzn-trace-id", "Root=1-abc-123")

    signed_request =
      AWSAuth.sign_authorization_header(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "GET",
        "https://examplebucket.s3.amazonaws.com/test.txt",
        "us-east-1",
        "s3",
        headers,
        "",
        @time
      )

    # Trace header should not appear in signed headers
    {"authorization", auth_value} = List.keyfind(signed_request, "authorization", 0)
    refute auth_value =~ "x-amzn-trace-id"

    # Trace header should not be in the returned headers
    refute List.keyfind(signed_request, "x-amzn-trace-id", 0)
  end

  test "sign_authorization_header normalizes header values with multiple spaces" do
    headers =
      Map.new()
      |> Map.put("Date", "Fri, 24 May 2013 00:00:00 GMT")
      |> Map.put("x-custom-header", "value  with   spaces")

    signed_request =
      AWSAuth.sign_authorization_header(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "GET",
        "https://examplebucket.s3.amazonaws.com/test.txt",
        "us-east-1",
        "s3",
        headers,
        "",
        @time
      )

    # Should normalize the header value
    {"x-custom-header", normalized_value} = List.keyfind(signed_request, "x-custom-header", 0)
    assert normalized_value == "value with spaces"
  end
end
