# Used by "mix format"
[
  subdirectories: ["priv/*/migrations"],
  plugins: [Quokka],
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}", "priv/*/seeds.exs"],
  quokka: [
    autosort: [:map, :defstruct],
    exclude: [],
    only: [
      :blocks,
      :configs,
      :defs,
      :deprecations,
      :module_directives,
      :pipes,
      :single_node
    ]
  ]
]
