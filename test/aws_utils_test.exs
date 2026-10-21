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

    assert AWSAuth.Utils.parse_aws_url("https://s3-fips.aws-global.amazonaws.com") ==
             {"s3", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://s3-fips.dualstack.us-east-1.amazonaws.com") ==
             {"s3", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://bucket.s3-fips.dualstack.us-west-2.amazonaws.com") ==
             {"s3", "us-west-2"}

    assert AWSAuth.Utils.parse_aws_url("https://s3-control.dualstack.us-east-1.amazonaws.com") ==
             {"s3", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://123456789012.s3-control-fips.dualstack.us-east-1.amazonaws.com"
           ) == {"s3", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://ap-123456789012.s3-accesspoint-fips.dualstack.us-west-2.amazonaws.com"
           ) == {"s3", "us-west-2"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://s3express-control-fips.dualstack.us-east-1.amazonaws.com"
           ) == {"s3express", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://bucket.s3express-fips-use1-az1.dualstack.us-east-1.amazonaws.com"
           ) == {"s3express", "us-east-1"}
  end

  test "parse_aws_url/1 uses botocore endpoint-prefix table and strips -fips" do
    assert AWSAuth.Utils.parse_aws_url("https://bedrock-agent.us-east-1.amazonaws.com") ==
             {"bedrock", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://bedrock-agent-runtime.us-east-1.amazonaws.com") ==
             {"bedrock", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://bedrock-data-automation.us-east-1.amazonaws.com") ==
             {"bedrock", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://bedrock-data-automation-runtime.us-east-1.amazonaws.com"
           ) == {"bedrock", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://email.us-east-1.amazonaws.com") ==
             {"ses", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://bedrock-agentcore.us-east-1.amazonaws.com") ==
             {"bedrock-agentcore", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://bedrock-agentcore-control.us-east-1.amazonaws.com"
           ) == {"bedrock-agentcore", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://api.ecr.us-east-1.amazonaws.com") ==
             {"ecr", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://runtime.sagemaker.us-east-1.amazonaws.com") ==
             {"sagemaker", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://a2i-runtime.sagemaker.us-east-1.amazonaws.com") ==
             {"sagemaker", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://lambda.us-east-1.amazonaws.com") ==
             {"lambda", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://lambda-fips.us-east-1.amazonaws.com") ==
             {"lambda", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://api-fips.sagemaker.us-east-1.amazonaws.com") ==
             {"sagemaker", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://data.iot-fips.us-east-1.amazonaws.com") ==
             {"iotdata", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://iam.global.api.aws") ==
             {"iam", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://importexport.amazonaws.com") ==
             {"IngestionService", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://api.tunneling.iot.us-east-1.amazonaws.com") ==
             {"IoTSecuredTunneling", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://data.ats.iot.cn-north-1.amazonaws.com.cn") ==
             {"iotdata", "cn-north-1"}

    assert AWSAuth.Utils.parse_aws_url("https://cn.transcribe.cn-north-1.amazonaws.com.cn") ==
             {"transcribe", "cn-north-1"}

    assert AWSAuth.Utils.parse_aws_url("https://api.iottwinmaker.us-east-1.amazonaws.com") ==
             {"iottwinmaker", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://verification.signer-fips.us-east-1.amazonaws.com") ==
             {"signer", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://global.health.amazonaws.com") ==
             {"health", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://global.health.amazonaws.com.cn") ==
             {"health", "cn-northwest-1"}

    assert AWSAuth.Utils.parse_aws_url("https://global.health.us-gov.amazonaws.com") ==
             {"health", "us-gov-west-1"}

    assert AWSAuth.Utils.parse_aws_url("https://budgets.amazonaws.com.cn") ==
             {"budgets", "cn-northwest-1"}

    assert AWSAuth.Utils.parse_aws_url("https://route53.amazonaws.com.cn") ==
             {"route53", "cn-northwest-1"}

    assert AWSAuth.Utils.parse_aws_url("https://route53.global.api.amazonwebservices.com.cn") ==
             {"route53", "cn-northwest-1"}

    assert AWSAuth.Utils.parse_aws_url("https://iam.global.api.amazonwebservices.com.cn") ==
             {"iam", "cn-north-1"}

    assert AWSAuth.Utils.parse_aws_url("https://codecatalyst.global.api.aws") ==
             {"codecatalyst", "aws-global"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://support.aws-cn-global.api.amazonwebservices.com.cn"
           ) == {"support", "cn-north-1"}

    assert AWSAuth.Utils.parse_aws_url("https://support.amazonaws.com.cn") ==
             {"support", "cn-north-1"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://route53-recovery-control-config.aws-global.api.aws"
           ) == {"route53-recovery-control-config", "us-west-2"}

    assert AWSAuth.Utils.parse_aws_url("https://networkmanager.aws-global.amazonaws.com") ==
             {"networkmanager", "us-west-2"}

    assert AWSAuth.Utils.parse_aws_url("https://S3.US-EAST-1.AMAZONAWS.COM/bucket/key") ==
             {"s3", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url(
             "https://myaccesspoint-123456789012.op-0123456789abcdef0.s3-outposts.us-east-1.amazonaws.com/a%20b.txt"
           ) == {"s3-outposts", "us-east-1"}

    assert AWSAuth.Utils.parse_aws_url("https://unknown.thing.us-east-1.amazonaws.com") ==
             {nil, nil}
  end

  test "build_canonical_request sorts canonical headers by header name, not name:value" do
    canonical =
      AWSAuth.Utils.build_canonical_request(
        "PUT",
        "/k",
        [],
        %{
          "host" => "example.com",
          "x-amz-meta-a" => "1",
          "x-amz-meta-a-b" => "2",
          "x-amz-meta-a1" => "3"
        },
        "hash",
        false
      )

    assert canonical ==
             "PUT\n/k\n\nhost:example.com\nx-amz-meta-a:1\nx-amz-meta-a-b:2\nx-amz-meta-a1:3\n\nhost;x-amz-meta-a;x-amz-meta-a-b;x-amz-meta-a1\nhash"
  end

  test "host_header/1 formats default ports, non-default ports, and IPv6 literals" do
    assert AWSAuth.Utils.host_header(URI.parse("https://h:443/")) == "h"
    assert AWSAuth.Utils.host_header(URI.parse("http://h:80/")) == "h"

    assert AWSAuth.Utils.host_header(URI.parse("http://localhost:4566/bucket/key")) ==
             "localhost:4566"

    assert AWSAuth.Utils.host_header(URI.parse("http://[::1]:4566/")) == "[::1]:4566"
    assert AWSAuth.Utils.host_header(URI.parse("http://[::1]/")) == "[::1]"
  end
end
