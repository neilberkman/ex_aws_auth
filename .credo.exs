%{
  configs: [
    %{
      name: "default",
      files: %{
        included: ["lib/", "test/"],
        excluded: [~r"/_build/", ~r"/deps/", ~r"/node_modules/"]
      },
      strict: true,
      checks: %{
        disabled: [
          # Disable arity check for public API functions to maintain backward compatibility
          # These functions use Elixir's function overloading pattern for optional parameters
          {Credo.Check.Refactor.FunctionArity, [
            files: %{
              excluded: [
                "lib/aws_auth.ex",
                "lib/aws_auth/authorization_header.ex",
                "lib/aws_auth/query_parameters.ex"
              ]
            }
          ]}
        ]
      }
    }
  ]
}
