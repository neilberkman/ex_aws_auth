defmodule AWSAuth.ReqTest do
  use ExUnit.Case, async: true

  alias AWSAuth.Credentials
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

  setup do
    credentials = %Credentials{
      access_key_id: "AKIDEXAMPLE",
      region: "us-east-1",
      secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }

    {:ok, credentials: credentials}
  end

  test "signs the encoded JSON body", %{credentials: credentials} do
    request =
      Req.new(
        adapter: CaptureAdapter,
        method: :post,
        url: "https://example.execute-api.us-east-1.amazonaws.com/items",
        json: %{name: "example"}
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach(credentials: credentials, service: "execute-api")
      |> run_and_capture_request()

    body = IO.iodata_to_binary(request.body)

    assert body == ~s({"name":"example"})

    assert Req.Request.get_header(request, "x-amz-content-sha256") == [
             AWSAuth.Utils.hash_sha256(body)
           ]
  end

  test "signs after applying base URL and query parameters", %{credentials: credentials} do
    request =
      Req.new(
        adapter: CaptureAdapter,
        base_url: "https://example.execute-api.us-east-1.amazonaws.com",
        url: "/items",
        params: [limit: 10]
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach(credentials: credentials, service: "execute-api")
      |> run_and_capture_request()

    assert URI.to_string(request.url) ==
             "https://example.execute-api.us-east-1.amazonaws.com/items?limit=10"

    assert Req.Request.get_header(request, "host") == [
             "example.execute-api.us-east-1.amazonaws.com"
           ]

    assert [authorization] = Req.Request.get_header(request, "authorization")
    assert [amz_date] = Req.Request.get_header(request, "x-amz-date")

    unsigned_headers =
      request.headers
      |> Map.delete("authorization")
      |> Map.new(fn {key, [value | _rest]} -> {key, value} end)

    expected_headers =
      AWSAuth.sign_authorization_header(
        credentials,
        "GET",
        URI.to_string(request.url),
        "execute-api",
        headers: unsigned_headers,
        payload: request.body || "",
        timestamp: parse_amz_date(amz_date),
        return_format: :map
      )

    assert authorization == expected_headers["authorization"]
  end

  test "signs a ReqLLM-style Bedrock request with temporary credentials", %{
    credentials: credentials
  } do
    session_token = "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
    credentials = %{credentials | session_token: session_token}
    body = ~s({"messages":[{"role":"user","content":[{"text":"Hello"}]}]})

    request =
      Req.new(
        adapter: CaptureAdapter,
        method: :post,
        url:
          "https://bedrock-runtime.us-east-1.amazonaws.com/model/global.anthropic.claude-sonnet-4-5-20250929-v1:0/converse",
        headers: %{"content-type" => "application/json"},
        body: body
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach(credentials: credentials, service: "bedrock")
      |> run_and_capture_request()

    assert request.body == body

    assert Req.Request.get_header(request, "x-amz-content-sha256") == [
             AWSAuth.Utils.hash_sha256(body)
           ]

    assert Req.Request.get_header(request, "x-amz-security-token") == [session_token]
    assert [authorization] = Req.Request.get_header(request, "authorization")
    assert authorization =~ "/us-east-1/bedrock/aws4_request"
    assert authorization =~ "x-amz-security-token"
  end

  test "re-signs retries without carrying headers from the prior attempt", %{
    credentials: credentials
  } do
    session_token = "current-session-token"
    credentials = %{credentials | session_token: session_token}

    request =
      Req.new(
        adapter: CaptureAdapter,
        method: :post,
        url: "https://bedrock-runtime.us-east-1.amazonaws.com/model/example/invoke",
        body: ~s({"prompt":"hello"})
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach(credentials: credentials, service: "bedrock")
      |> run_and_capture_request()

    signer = Keyword.fetch!(request.request_steps, :aws_sigv4)

    resigned_request =
      request
      |> Req.Request.put_header("authorization", "stale-authorization")
      |> Req.Request.put_header("x-amz-date", "20000101T000000Z")
      |> Req.Request.put_header("x-amz-content-sha256", "stale-payload-hash")
      |> Req.Request.put_header("x-amz-security-token", "stale-session-token")
      |> signer.()

    assert [authorization] = Req.Request.get_header(resigned_request, "authorization")
    refute authorization =~ "SignedHeaders=authorization"
    refute authorization =~ ";authorization"
    refute Req.Request.get_header(resigned_request, "x-amz-date") == ["20000101T000000Z"]

    assert Req.Request.get_header(resigned_request, "x-amz-content-sha256") == [
             AWSAuth.Utils.hash_sha256(resigned_request.body)
           ]

    assert Req.Request.get_header(resigned_request, "x-amz-security-token") == [session_token]
  end

  test "resolves region from URL when credentials have no region or a different region", %{
    credentials: credentials
  } do
    creds_no_region = %{credentials | region: nil}

    request =
      Req.new(
        adapter: CaptureAdapter,
        url: "https://b.s3.eu-west-1.amazonaws.com/k"
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach(credentials: creds_no_region, service: "s3")
      |> run_and_capture_request()

    assert [auth] = Req.Request.get_header(request, "authorization")
    assert auth =~ "/eu-west-1/s3/aws4_request"
  end

  test "preserves x-amzn-trace-id and unsigned_headers on outgoing Req request", %{
    credentials: credentials
  } do
    request =
      Req.new(
        adapter: CaptureAdapter,
        url: "https://b.s3.us-east-1.amazonaws.com/k",
        headers: %{
          "x-amzn-trace-id" => "Root=1-abc-123",
          "x-custom-unsigned" => "keep-me"
        }
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach(
        credentials: credentials,
        service: "s3",
        unsigned_headers: ["x-custom-unsigned"]
      )
      |> run_and_capture_request()

    assert Req.Request.get_header(request, "x-amzn-trace-id") == ["Root=1-abc-123"]
    assert Req.Request.get_header(request, "x-custom-unsigned") == ["keep-me"]
    assert Req.Request.get_header(request, "user-agent") != []
    assert [auth] = Req.Request.get_header(request, "authorization")
    refute auth =~ "x-amzn-trace-id"
    refute auth =~ "x-custom-unsigned"
    refute auth =~ "user-agent"
  end

  test "comma-joins multi-valued headers in Req request and signature (including identical values)",
       %{
         credentials: credentials
       } do
    request =
      Req.new(
        adapter: CaptureAdapter,
        url: "https://b.s3.us-east-1.amazonaws.com/k",
        headers: [
          {"x-amz-meta-tag", "a"},
          {"x-amz-meta-tag", "b"},
          {"x-amz-meta-dup", "a"},
          {"x-amz-meta-dup", "a"}
        ]
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach(credentials: credentials, service: "s3")
      |> run_and_capture_request()

    assert Req.Request.get_header(request, "x-amz-meta-tag") == ["a,b"]
    assert Req.Request.get_header(request, "x-amz-meta-dup") == ["a,a"]
    assert [auth] = Req.Request.get_header(request, "authorization")
    assert auth =~ "x-amz-meta-tag"
    assert auth =~ "x-amz-meta-dup"
  end

  test "streaming body with content-length signs as UNSIGNED-PAYLOAD; without content-length raises",
       %{credentials: credentials} do
    request =
      Req.new(
        adapter: CaptureAdapter,
        method: :put,
        url: "https://b.s3.us-east-1.amazonaws.com/k",
        body: Stream.map(["ab"], & &1),
        headers: %{"content-length" => "2"}
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach(credentials: credentials, service: "s3")
      |> run_and_capture_request()

    assert Req.Request.get_header(request, "x-amz-content-sha256") == ["UNSIGNED-PAYLOAD"]

    assert_raise ArgumentError, ~r/content-length/, fn ->
      Req.new(
        adapter: CaptureAdapter,
        method: :put,
        url: "https://b.s3.us-east-1.amazonaws.com/k",
        body: Stream.map(["ab"], & &1)
      )
      |> AWSReq.attach(credentials: credentials, service: "s3")
      |> Req.Request.run_request()
    end
  end

  test "attach payload: :streaming_events seeds STREAMING-AWS4-HMAC-SHA256-EVENTS", %{
    credentials: credentials
  } do
    request =
      Req.new(
        adapter: CaptureAdapter,
        method: :post,
        url:
          "https://bedrock-runtime.us-east-1.amazonaws.com/model/m/invoke-with-bidirectional-stream"
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> AWSReq.attach(credentials: credentials, service: "bedrock", payload: :streaming_events)
      |> run_and_capture_request()

    assert Req.Request.get_header(request, "x-amz-content-sha256") == [
             "STREAMING-AWS4-HMAC-SHA256-EVENTS"
           ]
  end

  test "attach rejects unknown options", %{credentials: credentials} do
    assert_raise ArgumentError, ~r/unknown keys/, fn ->
      Req.new(url: "https://b.s3.us-east-1.amazonaws.com/k")
      |> AWSReq.attach(credentials: credentials, service: "s3", bogus_opt: true)
    end
  end

  describe "redirects (D4)" do
    test "untrusted cross-origin redirect strips generated signing headers and host", %{
      credentials: credentials
    } do
      creds_with_token = %{credentials | session_token: "SESSION-TOKEN"}

      redirect_fun = fn req ->
        if req.url.host == "b.s3.us-east-1.amazonaws.com" do
          Req.Response.new(status: 302)
          |> Req.Response.put_header("location", "https://target.example/x")
        else
          Req.Response.new(status: 200)
        end
      end

      Req.new(
        adapter: CaptureAdapter,
        url: "https://b.s3.us-east-1.amazonaws.com/key",
        headers: %{
          "host" => "b.s3.us-east-1.amazonaws.com",
          "x-amz-security-token" => "CALLER-SUPPLIED-TOKEN"
        },
        redirect_log_level: false
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> Req.Request.put_private(:capture_redirect_fun, redirect_fun)
      |> AWSReq.attach(credentials: creds_with_token, service: "s3")
      |> Req.request!()

      assert_receive {:captured_request,
                      %{url: %URI{host: "b.s3.us-east-1.amazonaws.com"}} = first_req}

      assert Req.Request.get_header(first_req, "authorization") != []
      assert Req.Request.get_header(first_req, "x-amz-security-token") == ["SESSION-TOKEN"]

      assert_receive {:captured_request, %{url: %URI{host: "target.example"}} = redirected_req}
      assert Req.Request.get_header(redirected_req, "authorization") == []
      assert Req.Request.get_header(redirected_req, "x-amz-security-token") == []
      assert Req.Request.get_header(redirected_req, "x-amz-date") == []
      assert Req.Request.get_header(redirected_req, "x-amz-content-sha256") == []
      assert Req.Request.get_header(redirected_req, "host") == []
    end

    test "trusted cross-origin redirect re-signs with new host and region", %{
      credentials: credentials
    } do
      creds_with_token = %{credentials | session_token: "SESSION-TOKEN"}

      redirect_fun = fn req ->
        if req.url.host == "b.s3.us-east-1.amazonaws.com" do
          Req.Response.new(status: 301)
          |> Req.Response.put_header("location", "https://b.s3.eu-west-1.amazonaws.com/key")
        else
          Req.Response.new(status: 200)
        end
      end

      Req.new(
        adapter: CaptureAdapter,
        url: "https://b.s3.us-east-1.amazonaws.com/key",
        headers: %{"host" => "b.s3.us-east-1.amazonaws.com"},
        redirect_trusted: true,
        redirect_log_level: false
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> Req.Request.put_private(:capture_redirect_fun, redirect_fun)
      |> AWSReq.attach(credentials: creds_with_token, service: "s3")
      |> Req.request!()

      assert_receive {:captured_request,
                      %{url: %URI{host: "b.s3.us-east-1.amazonaws.com"}} = first_req}

      assert Req.Request.get_header(first_req, "host") == ["b.s3.us-east-1.amazonaws.com"]
      assert [first_auth] = Req.Request.get_header(first_req, "authorization")
      assert first_auth =~ "/us-east-1/s3/aws4_request"

      assert_receive {:captured_request,
                      %{url: %URI{host: "b.s3.eu-west-1.amazonaws.com"}} = second_req}

      assert Req.Request.get_header(second_req, "host") == ["b.s3.eu-west-1.amazonaws.com"]
      assert [second_auth] = Req.Request.get_header(second_req, "authorization")
      assert second_auth =~ "/eu-west-1/s3/aws4_request"
      refute second_auth == first_auth
    end

    test "same-origin redirect re-signs without requiring redirect_trusted", %{
      credentials: credentials
    } do
      redirect_fun = fn req ->
        if req.url.path == "/old" do
          Req.Response.new(status: 302)
          |> Req.Response.put_header("location", "/new")
        else
          Req.Response.new(status: 200)
        end
      end

      Req.new(
        adapter: CaptureAdapter,
        url: "https://b.s3.us-east-1.amazonaws.com/old",
        redirect_log_level: false
      )
      |> Req.Request.put_private(:capture_test_pid, self())
      |> Req.Request.put_private(:capture_redirect_fun, redirect_fun)
      |> AWSReq.attach(credentials: credentials, service: "s3")
      |> Req.request!()

      assert_receive {:captured_request, %{url: %URI{path: "/old"}} = first_req}
      assert [first_auth] = Req.Request.get_header(first_req, "authorization")

      assert_receive {:captured_request, %{url: %URI{path: "/new"}} = second_req}
      assert [second_auth] = Req.Request.get_header(second_req, "authorization")
      refute second_auth == first_auth
    end
  end

  defp run_and_capture_request(request) do
    assert {_request, %Req.Response{status: 200}} = Req.Request.run_request(request)
    assert_receive {:captured_request, captured_request}
    captured_request
  end

  defp parse_amz_date(
         <<year::binary-size(4), month::binary-size(2), day::binary-size(2), "T",
           hour::binary-size(2), minute::binary-size(2), second::binary-size(2), "Z">>
       ) do
    date = Date.new!(String.to_integer(year), String.to_integer(month), String.to_integer(day))

    time =
      Time.new!(String.to_integer(hour), String.to_integer(minute), String.to_integer(second))

    NaiveDateTime.new!(date, time)
  end
end
