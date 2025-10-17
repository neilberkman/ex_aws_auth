defmodule AWSAuth.CredentialsTest do
  use ExUnit.Case, async: false

  alias AWSAuth.Credentials

  describe "struct" do
    test "can be created with all fields" do
      creds = %Credentials{
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        region: "us-east-1",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token: "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
      }

      assert creds.access_key_id == "AKIAIOSFODNN7EXAMPLE"
      assert creds.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      assert creds.session_token == "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
      assert creds.region == "us-east-1"
    end

    test "can be created with minimal fields" do
      creds = %Credentials{
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      }

      assert creds.access_key_id == "AKIAIOSFODNN7EXAMPLE"
      assert creds.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      assert is_nil(creds.session_token)
      assert is_nil(creds.region)
    end
  end

  describe "from_env/0" do
    setup do
      # Save existing env vars
      old_env = %{
        access_key: System.get_env("AWS_ACCESS_KEY_ID"),
        default_region: System.get_env("AWS_DEFAULT_REGION"),
        region: System.get_env("AWS_REGION"),
        secret_key: System.get_env("AWS_SECRET_ACCESS_KEY"),
        session_token: System.get_env("AWS_SESSION_TOKEN")
      }

      # Clean environment
      System.delete_env("AWS_ACCESS_KEY_ID")
      System.delete_env("AWS_SECRET_ACCESS_KEY")
      System.delete_env("AWS_SESSION_TOKEN")
      System.delete_env("AWS_REGION")
      System.delete_env("AWS_DEFAULT_REGION")

      on_exit(fn ->
        # Restore environment
        if old_env.access_key, do: System.put_env("AWS_ACCESS_KEY_ID", old_env.access_key)
        if old_env.secret_key, do: System.put_env("AWS_SECRET_ACCESS_KEY", old_env.secret_key)
        if old_env.session_token, do: System.put_env("AWS_SESSION_TOKEN", old_env.session_token)
        if old_env.region, do: System.put_env("AWS_REGION", old_env.region)

        if old_env.default_region,
          do: System.put_env("AWS_DEFAULT_REGION", old_env.default_region)
      end)

      :ok
    end

    test "returns nil when environment variables are not set" do
      assert Credentials.from_env() == nil
    end

    test "returns nil when only access key is set" do
      System.put_env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
      assert Credentials.from_env() == nil
    end

    test "returns nil when only secret key is set" do
      System.put_env("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
      assert Credentials.from_env() == nil
    end

    test "returns credentials with required fields" do
      System.put_env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
      System.put_env("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

      creds = Credentials.from_env()

      assert creds.access_key_id == "AKIAIOSFODNN7EXAMPLE"
      assert creds.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      assert is_nil(creds.session_token)
      assert is_nil(creds.region)
    end

    test "includes session token when set" do
      System.put_env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
      System.put_env("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
      System.put_env("AWS_SESSION_TOKEN", "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123")

      creds = Credentials.from_env()

      assert creds.session_token == "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
    end

    test "includes region from AWS_REGION" do
      System.put_env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
      System.put_env("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
      System.put_env("AWS_REGION", "us-west-2")

      creds = Credentials.from_env()

      assert creds.region == "us-west-2"
    end

    test "includes region from AWS_DEFAULT_REGION as fallback" do
      System.put_env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
      System.put_env("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
      System.put_env("AWS_DEFAULT_REGION", "eu-west-1")

      creds = Credentials.from_env()

      assert creds.region == "eu-west-1"
    end

    test "AWS_REGION takes precedence over AWS_DEFAULT_REGION" do
      System.put_env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
      System.put_env("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
      System.put_env("AWS_REGION", "us-west-2")
      System.put_env("AWS_DEFAULT_REGION", "eu-west-1")

      creds = Credentials.from_env()

      assert creds.region == "us-west-2"
    end
  end

  describe "from_map/1" do
    test "creates credentials from map with string keys" do
      creds =
        Credentials.from_map(%{
          "access_key_id" => "AKIAIOSFODNN7EXAMPLE",
          "region" => "us-east-1",
          "secret_access_key" => "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        })

      assert creds.access_key_id == "AKIAIOSFODNN7EXAMPLE"
      assert creds.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      assert creds.region == "us-east-1"
    end

    test "creates credentials from map with atom keys" do
      creds =
        Credentials.from_map(%{
          access_key_id: "AKIAIOSFODNN7EXAMPLE",
          region: "us-west-2",
          secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          session_token: "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
        })

      assert creds.access_key_id == "AKIAIOSFODNN7EXAMPLE"
      assert creds.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      assert creds.session_token == "FwoGZXIvYXdzEBYaDHhBTEMPLESessionToken123"
      assert creds.region == "us-west-2"
    end

    test "creates credentials from keyword list" do
      creds =
        Credentials.from_map(
          access_key_id: "AKIAIOSFODNN7EXAMPLE",
          secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

      assert creds.access_key_id == "AKIAIOSFODNN7EXAMPLE"
      assert creds.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    end

    test "handles missing optional fields" do
      creds =
        Credentials.from_map(%{
          access_key_id: "AKIAIOSFODNN7EXAMPLE",
          secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        })

      assert is_nil(creds.session_token)
      assert is_nil(creds.region)
    end
  end
end
