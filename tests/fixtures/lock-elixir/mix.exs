defmodule Fixture.MixProject do
  use Mix.Project
  def project, do: [app: :fixture, version: "0.1.0", elixir: "~> 1.15", deps: deps()]
  def application, do: [extra_applications: [:logger]]
  defp deps do
    [
      {:phoenix, "~> 1.7"},
      {:jason, "~> 1.4"},
      {:plug_cowboy, "~> 2.7"},
      {:decimal, git: "https://github.com/ericmj/decimal.git", tag: "v2.1.1", override: true},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
