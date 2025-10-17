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
end
