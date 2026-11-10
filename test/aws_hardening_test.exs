defmodule AWSAuth.HardeningTest do
  use ExUnit.Case, async: true

  alias AWSAuth.Credentials
  alias AWSAuth.EventStream
  alias AWSAuth.Req, as: AWSReq

  defmodule CaptureAdapter do
    def run(request) do
      request
      |> Req.Request.get_private(:capture_test_pid)
      |> send({:captured_request, request})

      case Req.Request.get_private(request, :capture_redirect_fun) do
        nil -> {request, Req.Response.new(status: 200)}
        fun -> {request, fun.(request)}
      end
    end
  end

  @time ~N[2025-01-01 00:00:00]
  @url "https://s3.us-east-1.amazonaws.com/b/k"
  @creds %Credentials{
    access_key_id: "AKIDEXAMPLE",
    region: "us-east-1",
    secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }

  describe "credential validation" do
    test "header and URL signing raise on a missing access key or secret" do
      for creds <- [
            Credentials.from_map(%{}),
            %{@creds | access_key_id: nil},
            %{@creds | access_key_id: ""},
            %{@creds | secret_access_key: nil},
            %{@creds | secret_access_key: ""}
          ] do
        assert_raise ArgumentError, ~r/is missing/, fn ->
          AWSAuth.sign_authorization_header(creds, "GET", @url, "s3", timestamp: @time)
        end

        assert_raise ArgumentError, ~r/is missing/, fn ->
          AWSAuth.sign_url(creds, "GET", @url, "s3", timestamp: @time)
        end
      end
    end

    test "the error never contains the other credential" do
      error =
        assert_raise ArgumentError, fn ->
          AWSAuth.sign_url(%{@creds | access_key_id: nil}, "GET", @url, "s3")
        end

      refute Exception.message(error) =~ @creds.secret_access_key
    end

    test "event signing requires the secret but not the access key" do
      secret_only = %Credentials{secret_access_key: "SK", region: "us-east-1"}
      assert {_frame, _sig} = EventStream.sign_message(secret_only, "bedrock", "00", "p", @time)

      assert_raise ArgumentError, ~r/secret access key is missing/, fn ->
        EventStream.sign_message(%Credentials{region: "us-east-1"}, "bedrock", "00", "p", @time)
      end
    end
  end

  describe "URL validation" do
    test "a URL without a host raises" do
      assert_raise ArgumentError, ~r/without a host/, fn ->
        AWSAuth.sign_authorization_header(@creds, "GET", "s3.us-east-1.amazonaws.com/b/k", "s3")
      end

      assert_raise ArgumentError, ~r/without a host/, fn ->
        AWSAuth.sign_url(@creds, "GET", "s3.us-east-1.amazonaws.com/b/k", "s3")
      end
    end

    test "scheme-relative and non-HTTP URLs raise" do
      for url <- [
            "//s3.us-east-1.amazonaws.com/b/k",
            "//s3.us-east-1.amazonaws.com:443/b/k",
            "javascript://s3.us-east-1.amazonaws.com/x",
            "ftp://s3.us-east-1.amazonaws.com/b/k"
          ] do
        assert_raise ArgumentError, ~r/absolute http/, fn ->
          AWSAuth.sign_url(@creds, "GET", url, "s3")
        end

        assert_raise ArgumentError, ~r/absolute http/, fn ->
          AWSAuth.sign_authorization_header(@creds, "GET", url, "s3")
        end
      end
    end

    test "wss URLs can be presigned" do
      url =
        "wss://transcribestreaming.us-east-1.amazonaws.com:8443/stream-transcription-websocket"

      signed = AWSAuth.sign_url(@creds, "GET", url, "transcribe", timestamp: @time)
      assert String.starts_with?(signed, url <> "?")
    end

    test "the signed host is lowercased, matching botocore" do
      upper = "https://B.S3.US-EAST-1.AMAZONAWS.COM/b/k"
      lower = "https://b.s3.us-east-1.amazonaws.com/b/k"

      assert AWSAuth.sign_url(@creds, "GET", upper, "s3", timestamp: @time) ==
               AWSAuth.sign_url(@creds, "GET", lower, "s3", timestamp: @time)

      headers =
        AWSAuth.sign_authorization_header(@creds, "GET", upper, "s3",
          timestamp: @time,
          return_format: :map
        )

      assert headers["host"] == "b.s3.us-east-1.amazonaws.com"
    end

    test "positional signers validate credentials and URLs too" do
      assert_raise ArgumentError, ~r/is missing/, fn ->
        AWSAuth.sign_url("AK", nil, "GET", @url, "us-east-1", "s3")
      end

      assert_raise ArgumentError, ~r/is missing/, fn ->
        AWSAuth.sign_authorization_header("", "SK", "GET", @url, "us-east-1", "s3")
      end

      assert_raise ArgumentError, ~r/without a host/, fn ->
        AWSAuth.sign_url("AK", "SK", "GET", "s3.amazonaws.com/b/k", "us-east-1", "s3")
      end
    end

    test "presigned URLs drop userinfo" do
      signed =
        AWSAuth.sign_url(@creds, "GET", "https://user:pw@s3.us-east-1.amazonaws.com/b/k", "s3",
          timestamp: @time
        )

      assert String.starts_with?(signed, "https://s3.us-east-1.amazonaws.com/b/k?")
      refute signed =~ "user"
    end

    test "presigned URLs keep a non-default port" do
      signed =
        AWSAuth.sign_url(@creds, "GET", "http://localhost:9000/b/k", "s3", timestamp: @time)

      assert String.starts_with?(signed, "http://localhost:9000/b/k?")
    end
  end

  describe "presigned query parameters" do
    test "case variants of SigV4 parameters in the input URL are dropped" do
      url =
        @url <>
          "?x-amz-expires=604800&X-AMZ-SIGNATURE=dead&x-amz-credential=evil" <>
          "&x-amz-security-token=tok&versionId=3"

      signed = AWSAuth.sign_url(@creds, "GET", url, "s3", timestamp: @time)

      params =
        signed |> URI.parse() |> Map.fetch!(:query) |> URI.query_decoder() |> Enum.to_list()

      names = Enum.map(params, &elem(&1, 0))

      assert Enum.sort(names) ==
               Enum.sort([
                 "X-Amz-Algorithm",
                 "X-Amz-Credential",
                 "X-Amz-Date",
                 "X-Amz-Expires",
                 "X-Amz-Signature",
                 "X-Amz-SignedHeaders",
                 "versionId"
               ])

      assert {"X-Amz-Expires", "900"} in params
      refute {"X-Amz-Signature", "dead"} in params
    end
  end

  describe "presigned query parameters (encoded and remaining names)" do
    test "percent-encoded and remaining SigV4 names are dropped" do
      url =
        @url <>
          "?%78-amz-expires=604800&x-amz-algorithm=X&x-amz-date=Y" <>
          "&x-amz-signedheaders=Z&x-amz-s3session-token=T"

      signed = AWSAuth.sign_url(@creds, "GET", url, "s3", timestamp: @time)

      names =
        signed
        |> URI.parse()
        |> Map.fetch!(:query)
        |> URI.query_decoder()
        |> Enum.map(&elem(&1, 0))

      assert Enum.sort(names) ==
               Enum.sort([
                 "X-Amz-Algorithm",
                 "X-Amz-Credential",
                 "X-Amz-Date",
                 "X-Amz-Expires",
                 "X-Amz-Signature",
                 "X-Amz-SignedHeaders"
               ])
    end

    test "sign_url rejects invalid header names" do
      assert_raise ArgumentError, ~r/invalid header name/, fn ->
        AWSAuth.sign_url(@creds, "GET", @url, "s3", headers: %{"x bad" => "1"})
      end
    end
  end

  describe "header names" do
    test "names that are not RFC 7230 tokens raise" do
      for name <- ["x-bad\r\nname", "x bad", "x:bad", ""] do
        assert_raise ArgumentError, ~r/invalid header name/, fn ->
          AWSAuth.sign_authorization_header(@creds, "GET", @url, "s3", headers: %{name => "1"})
        end

        assert_raise ArgumentError, ~r/invalid header name/, fn ->
          AWSAuth.sign_authorization_header(@creds, "GET", @url, "s3", headers: [{name, "1"}])
        end
      end
    end

    test "atom and mixed-case token names are accepted" do
      headers =
        AWSAuth.sign_authorization_header(@creds, "GET", @url, "s3",
          headers: %{:"X-Amz-Meta-A" => "1", "Content-Type" => "text/plain"},
          return_format: :map
        )

      assert headers["x-amz-meta-a"] == "1"
      assert headers["content-type"] == "text/plain"
    end
  end

  describe "event stream encoding limits" do
    test "header values over 32767 bytes raise instead of wrapping the length" do
      assert <<2, ":x", 7, 127, 255, _::binary>> =
               EventStream.encode_string_header(":x", String.duplicate("a", 32_767))

      for size <- [32_768, 65_541] do
        value = String.duplicate("a", size)

        assert_raise ArgumentError, ~r/maximum is 32767/, fn ->
          EventStream.encode_string_header(":x", value)
        end

        assert_raise ArgumentError, ~r/maximum is 32767/, fn ->
          EventStream.encode_byte_array_header(":x", value)
        end
      end
    end

    test "header names over 255 bytes or empty raise" do
      assert <<255, _::binary>> =
               EventStream.encode_string_header(String.duplicate("n", 255), "v")

      for name <- [String.duplicate("n", 256), ""] do
        assert_raise ArgumentError, ~r/header name must be/, fn ->
          EventStream.encode_string_header(name, "v")
        end

        assert_raise ArgumentError, ~r/header name must be/, fn ->
          EventStream.encode_timestamp_header(name, @time)
        end
      end
    end

    test "byte-array header names are bounded too" do
      assert_raise ArgumentError, ~r/header name must be/, fn ->
        EventStream.encode_byte_array_header(String.duplicate("n", 256), "v")
      end
    end

    test "names and string values must be valid UTF-8 binaries" do
      assert_raise ArgumentError, ~r/valid UTF-8/, fn ->
        EventStream.encode_string_header(":content-type", <<0xFF, 0xFE>>)
      end

      for name <- [<<0xFF>>, <<1::1>>, :date] do
        assert_raise ArgumentError, ~r/must be a UTF-8 string/, fn ->
          EventStream.encode_string_header(name, "v")
        end
      end

      # byte-array values are arbitrary bytes
      assert is_binary(EventStream.encode_byte_array_header(":sig", <<0xFF, 0xFE>>))
    end

    test "encode_message enforces the 128 KiB header and 24 MiB payload limits" do
      at_limit = :binary.copy(<<0>>, 128 * 1024)
      assert is_binary(EventStream.encode_message(at_limit, ""))

      assert_raise ArgumentError, ~r/headers are 131073 bytes/, fn ->
        EventStream.encode_message(at_limit <> <<0>>, "")
      end

      assert_raise ArgumentError, ~r/payload is 25165825 bytes/, fn ->
        EventStream.encode_message("", :binary.copy(<<0>>, 24 * 1024 * 1024 + 1))
      end
    end

    test "a non-UTC DateTime signs the same as the equal UTC instant" do
      pst = %DateTime{
        year: 2025,
        month: 1,
        day: 1,
        hour: 20,
        minute: 0,
        second: 0,
        microsecond: {0, 0},
        time_zone: "America/Los_Angeles",
        zone_abbr: "PST",
        utc_offset: -28_800,
        std_offset: 0
      }

      utc = ~U[2025-01-02 04:00:00Z]

      assert EventStream.sign_message(@creds, "transcribe", "00", "p", pst) ==
               EventStream.sign_message(@creds, "transcribe", "00", "p", utc)
    end
  end

  describe "Req redirects" do
    defp redirecting_request(location, opts) do
      redirect_fun = fn req ->
        if req.url.host == "b.s3.us-east-1.amazonaws.com" do
          Req.Response.new(status: 307) |> Req.Response.put_header("location", location)
        else
          Req.Response.new(status: 200)
        end
      end

      [
        adapter: CaptureAdapter,
        url: "https://b.s3.us-east-1.amazonaws.com/key",
        redirect_log_level: false
      ]
      |> Keyword.merge(opts)
      |> Req.new()
      |> Req.Request.put_private(:capture_test_pid, self())
      |> Req.Request.put_private(:capture_redirect_fun, redirect_fun)
      |> AWSReq.attach(credentials: %{@creds | session_token: "SESSION-TOKEN"}, service: "s3")
      |> Req.request!()
    end

    test "untrusted redirect strips caller-supplied x-amz-* headers" do
      redirecting_request("https://target.example/x",
        headers: %{
          "x-amz-server-side-encryption-customer-key" => "SSE-C-KEY",
          "X-Amz-Meta-Owner" => "me",
          "x-amzn-other" => "kept",
          "content-type" => "text/plain"
        }
      )

      assert_receive {:captured_request,
                      %{url: %URI{host: "b.s3.us-east-1.amazonaws.com"}} = first}

      assert Req.Request.get_header(first, "x-amz-server-side-encryption-customer-key") == [
               "SSE-C-KEY"
             ]

      assert_receive {:captured_request, %{url: %URI{host: "target.example"}} = second}

      for name <- Map.keys(second.headers) do
        refute String.starts_with?(String.downcase(name), "x-amz-"), "leaked #{name}"
      end

      assert Req.Request.get_header(second, "authorization") == []
      assert Req.Request.get_header(second, "content-type") == ["text/plain"]
      assert Req.Request.get_header(second, "x-amzn-other") == ["kept"]
    end

    test "redirect_trusted does not re-sign for a non-AWS host" do
      redirecting_request("https://target.example/x", redirect_trusted: true)

      assert_receive {:captured_request, %{url: %URI{host: "b.s3.us-east-1.amazonaws.com"}}}
      assert_receive {:captured_request, %{url: %URI{host: "target.example"}} = second}
      assert Req.Request.get_header(second, "authorization") == []
      assert Req.Request.get_header(second, "x-amz-security-token") == []
      assert Req.Request.get_header(second, "x-amz-date") == []
    end

    test "redirect_trusted re-signs for another AWS endpoint" do
      redirecting_request("https://b.s3.eu-west-1.amazonaws.com/key", redirect_trusted: true)

      assert_receive {:captured_request, %{url: %URI{host: "b.s3.us-east-1.amazonaws.com"}}}

      assert_receive {:captured_request,
                      %{url: %URI{host: "b.s3.eu-west-1.amazonaws.com"}} = second}

      assert [auth] = Req.Request.get_header(second, "authorization")
      assert auth =~ "/eu-west-1/s3/aws4_request"
    end
  end

  describe "Req trusted redirects are limited to the signed service over https" do
    test "hosts under amazonaws.com that are not the signed service are not re-signed" do
      for location <- [
            "https://ec2-54-210-1-2.compute-1.amazonaws.com/collect",
            "https://other.s3-website-us-east-1.amazonaws.com/collect",
            "https://sts.us-east-1.amazonaws.com/",
            "http://b.s3.eu-west-1.amazonaws.com/key"
          ] do
        redirecting_request(location,
          redirect_trusted: true,
          headers: %{"x-amz-server-side-encryption-customer-key" => "SSE-C-KEY"}
        )

        assert_receive {:captured_request, %{url: %URI{host: "b.s3.us-east-1.amazonaws.com"}}}
        assert_receive {:captured_request, second}
        assert URI.to_string(second.url) == location

        for name <- ["authorization", "x-amz-security-token", "x-amz-date", "host"] do
          assert Req.Request.get_header(second, name) == [], "#{name} sent to #{location}"
        end

        assert Req.Request.get_header(second, "x-amz-server-side-encryption-customer-key") == []
      end
    end

    test "the S3 Express session token is stripped as well" do
      redirect_fun = fn req ->
        if req.url.host == "target.example" do
          Req.Response.new(status: 200)
        else
          Req.Response.new(status: 307)
          |> Req.Response.put_header("location", "https://target.example/x")
        end
      end

      Req.new(
        adapter: CaptureAdapter,
        url: "https://b--use1-az4--x-s3.s3express-use1-az4.us-east-1.amazonaws.com/key",
        redirect_log_level: false
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> Req.Request.put_private(:capture_redirect_fun, redirect_fun)
      |> AWSReq.attach(
        credentials: %{@creds | session_token: "EXPRESS-TOKEN"},
        service: "s3express",
        auth_scheme: :s3express_session
      )
      |> Req.request!()

      assert_receive {:captured_request, first}
      assert Req.Request.get_header(first, "x-amz-s3session-token") == ["EXPRESS-TOKEN"]
      assert_receive {:captured_request, %{url: %URI{host: "target.example"}} = second}
      assert Req.Request.get_header(second, "x-amz-s3session-token") == []
    end

    test "once a redirect is untrusted, a later hop back to AWS is not re-signed" do
      redirect_fun = fn req ->
        case {req.url.host, req.url.path} do
          {"b.s3.us-east-1.amazonaws.com", "/key"} ->
            Req.Response.new(status: 307)
            |> Req.Response.put_header("location", "https://target.example/x")

          {"target.example", _path} ->
            Req.Response.new(status: 307)
            |> Req.Response.put_header("location", "https://b.s3.us-east-1.amazonaws.com/other")

          _final ->
            Req.Response.new(status: 200)
        end
      end

      Req.new(
        adapter: CaptureAdapter,
        url: "https://b.s3.us-east-1.amazonaws.com/key",
        redirect_trusted: true,
        redirect_log_level: false
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> Req.Request.put_private(:capture_redirect_fun, redirect_fun)
      |> AWSReq.attach(credentials: %{@creds | session_token: "SESSION-TOKEN"}, service: "s3")
      |> Req.request!()

      assert_receive {:captured_request, %{url: %URI{path: "/key"}} = first}
      assert Req.Request.get_header(first, "authorization") != []
      assert_receive {:captured_request, %{url: %URI{host: "target.example"}}}
      assert_receive {:captured_request, %{url: %URI{path: "/other"}} = third}
      assert Req.Request.get_header(third, "authorization") == []
      assert Req.Request.get_header(third, "x-amz-security-token") == []
    end
  end

  describe "Req streaming bodies" do
    defp streaming_request(url, attach_opts) do
      Req.new(
        adapter: CaptureAdapter,
        method: :put,
        url: url,
        body: Stream.map(["a", "b"], & &1),
        headers: %{"content-length" => "2"}
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach([credentials: @creds, service: "s3"] ++ attach_opts)
      |> Req.request!()
    end

    test "https signs a streamed body as UNSIGNED-PAYLOAD" do
      streaming_request("https://b.s3.us-east-1.amazonaws.com/key", [])
      assert_receive {:captured_request, request}
      assert Req.Request.get_header(request, "x-amz-content-sha256") == ["UNSIGNED-PAYLOAD"]
    end

    test "plain http raises unless payload: :unsigned is given" do
      assert_raise ArgumentError, ~r/pass payload: :unsigned/, fn ->
        streaming_request("http://localhost:9000/b/key", [])
      end

      streaming_request("http://localhost:9000/b/key", payload: :unsigned)
      assert_receive {:captured_request, request}
      assert Req.Request.get_header(request, "x-amz-content-sha256") == ["UNSIGNED-PAYLOAD"]
    end
  end
end
