defmodule ExAWSAuth.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_aws_auth,
      version: "1.2.0",
      elixir: "~> 1.14",
      description: description(),
      package: package(),
      deps: deps(),
      test_coverage: [tool: ExCoveralls]
    ]
  end

  def cli do
    [
      preferred_envs: [coveralls: :test]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp deps do
    [
      # Optional: Req plugin support
      {:req, "~> 0.5", optional: true},
      {:jason, "~> 1.4", optional: true},

      # Dev/Test dependencies
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:quokka, "~> 2.11", only: :dev}
    ]
  end

  defp description do
    """
    AWS Signature Version 4 Signing Library - Community-maintained fork
    """
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*", "LICENSE", "CHANGELOG.md"],
      maintainers: ["Neil Berkman"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/neilberkman/ex_aws_auth"}
    ]
  end
end
