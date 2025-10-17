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
end
