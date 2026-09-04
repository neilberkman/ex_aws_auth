defmodule AWSAuth.ReqTest do
  use ExUnit.Case, async: true

  alias AWSAuth.Credentials
  alias AWSAuth.Req, as: AWSReq

  defmodule CaptureAdapter do
    def run(request) do
      request
      |> Req.Request.get_private(:capture_test_pid)
      |> send({:captured_request, request})

      {request, Req.Response.new(status: 200)}
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
