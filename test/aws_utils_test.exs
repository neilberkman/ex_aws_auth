defmodule AWSAuth.UtilsTest do
  use ExUnit.Case

  test "build_canonical_request/5 builds correct AWS request representation" do
    canonical_request =
      AWSAuth.Utils.build_canonical_request(
        "GET",
        "path/subpath",
        %{"a" => 1, "b" => "2", "c" => 1.0},
        %{"a" => "1", "b" => "2"},
        "hashed_payload"
      )

    assert canonical_request ==
             "GET\npath/subpath\na=1&b=2&c=1.0\na:1\nb:2\n\na;b\nhashed_payload"
  end

  test "build_canonical_request/5 builds correct AWS request representation with unsigned hash_payload" do
    canonical_request =
      AWSAuth.Utils.build_canonical_request(
        "GET",
        "path/subpath",
        %{"a" => 1, "b" => "2", "c" => 1.0},
        %{"a" => "1", "b" => "2"},
        :unsigned
      )

    assert canonical_request ==
             "GET\npath/subpath\na=1&b=2&c=1.0\na:1\nb:2\n\na;b\nUNSIGNED-PAYLOAD"
  end

  test "build_canonical_request/5 builds correct AWS request representation correctly escaped" do
    canonical_request =
      AWSAuth.Utils.build_canonical_request(
        "GET",
        "path/subpath/!@#$%^&*()-_=+?,.<>;:'\"[]{}|\\~`",
        %{},
        %{},
        ""
      )

    assert canonical_request ==
             "GET\npath/subpath/%21%40%23%24%25%5E%26%2A%28%29-_%3D%2B%3F%2C.%3C%3E%3B%3A%27%22%5B%5D%7B%7D%7C%5C~%60\n\n\n\n\n"
  end

  test "build_canonical_request/5 encodes path spaces as percent-20" do
    canonical_request =
      AWSAuth.Utils.build_canonical_request(
        "GET",
        "/folder/a b",
        %{},
        %{},
        "hashed_payload"
      )

    assert canonical_request == "GET\n/folder/a%20b\n\n\n\n\nhashed_payload"
  end

  test "canonical_query_string/1 sorts encoded pairs and preserves duplicate keys" do
    params = [{"z", "last"}, {"a", "two words"}, {"a", "one"}]

    assert AWSAuth.Utils.canonical_query_string(params) == "a=one&a=two%20words&z=last"
  end

  test "uri_encode/1 handles reserved and multi-byte characters" do
    assert AWSAuth.Utils.uri_encode("+*é") == "%2B%2A%C3%A9"
  end

  test "canonical_query_string/1 emits an equals sign for an empty value" do
    assert AWSAuth.Utils.canonical_query_string([{"acl", ""}]) == "acl="
  end

  test "format_time/1 formats a time correctly" do
    time = AWSAuth.Utils.format_time(~N[2016-10-20 10:32:45.12345])
    assert time == "20161020T103245Z"
  end

  test "filter_unsignable_headers/1 removes x-amzn-trace-id headers" do
    headers = %{
      "host" => "example.com",
      "x-amz-date" => "20130524T000000Z",
      "x-amzn-trace-id" => "Root=1-abc-123"
    }

    filtered = AWSAuth.Utils.filter_unsignable_headers(headers)

    assert filtered == %{
             "host" => "example.com",
             "x-amz-date" => "20130524T000000Z"
           }
  end

  test "filter_unsignable_headers/1 removes x-amzn-trace-id headers case insensitively" do
    headers = %{
      "Host" => "example.com",
      "X-Amzn-Trace-Id" => "Root=1-abc-123",
      "x-amz-date" => "20130524T000000Z"
    }

    filtered = AWSAuth.Utils.filter_unsignable_headers(headers)

    assert filtered == %{
             "Host" => "example.com",
             "x-amz-date" => "20130524T000000Z"
           }
  end

  test "normalize_header_values/1 collapses multiple spaces" do
    headers = %{
      "authorization" => "AWS   SOMETHING",
      "host" => "example.com",
      "x-custom" => "value  with   multiple    spaces"
    }

    normalized = AWSAuth.Utils.normalize_header_values(headers)

    assert normalized == %{
             "authorization" => "AWS SOMETHING",
             "host" => "example.com",
             "x-custom" => "value with multiple spaces"
           }
  end

  test "normalize_header_values/1 handles already normalized headers" do
    headers = %{
      "authorization" => "AWS SOMETHING",
      "host" => "example.com"
    }

    normalized = AWSAuth.Utils.normalize_header_values(headers)

    assert normalized == headers
  end

  test "validate_query_params/1 accepts valid parameters" do
    params = %{"key1" => "value1", "key2" => 123, "key3" => 1.5}
    assert AWSAuth.Utils.validate_query_params(params) == params
  end

  test "validate_query_params/1 rejects list keys" do
    params = %{["key1"] => "value1"}

    assert_raise ArgumentError, ~r/Query parameter keys and values cannot be lists/, fn ->
      AWSAuth.Utils.validate_query_params(params)
    end
  end

  test "validate_query_params/1 rejects list values" do
    params = %{"key1" => ["value1", "value2"]}

    assert_raise ArgumentError, ~r/Query parameter keys and values cannot be lists/, fn ->
      AWSAuth.Utils.validate_query_params(params)
    end
  end

  test "parse_aws_url/1 recognizes a global virtual-hosted S3 URL" do
    assert AWSAuth.Utils.parse_aws_url("https://bucket.s3.amazonaws.com/key") ==
             {"s3", "us-east-1"}
  end

  test "parse_aws_url/1 recognizes dotted, dual-stack, China, and legacy S3 URLs" do
    assert AWSAuth.Utils.parse_aws_url("https://my.bucket.s3.amazonaws.com/key") ==
             {"s3", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://my.bucket.s3.dualstack.us-west-2.amazonaws.com/key"
           ) == {"s3", "us-west-2"}

    assert AWSAuth.Utils.parse_aws_url("https://bucket.s3.cn-north-1.amazonaws.com.cn/key") ==
             {"s3", "cn-north-1"}

    assert AWSAuth.Utils.parse_aws_url("https://bucket.s3-us-west-2.amazonaws.com/key") ==
             {"s3", "us-west-2"}
  end

  test "parse_aws_url/1 uses the rightmost S3 label for a dotted bucket" do
    assert AWSAuth.Utils.parse_aws_url("https://s3.example.com.s3.us-west-2.amazonaws.com/key") ==
             {"s3", "us-west-2"}
  end

  test "parse_aws_url/1 preserves specialized S3 signing names" do
    assert AWSAuth.Utils.parse_aws_url("https://s3-outposts.us-west-2.amazonaws.com") ==
             {"s3-outposts", "us-west-2"}

    assert AWSAuth.Utils.parse_aws_url("https://s3-object-lambda.us-west-2.amazonaws.com") ==
             {"s3-object-lambda", "us-west-2"}

    assert AWSAuth.Utils.parse_aws_url("https://s3-control.us-west-2.amazonaws.com") ==
             {"s3", "us-west-2"}
  end
end
