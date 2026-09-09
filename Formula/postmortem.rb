class Postmortem < Formula
  desc "Supply-chain scanner. Flags malicious install code, typosquats, and shady provenance across your dependencies and your OS packages. Repo-reputation scoring, known-CVE intel, no telemetry."
  homepage "https://github.com/mlab-sh/postmortem"
  version "2.4.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "2f004ffd07ac3d8d1f2bc4ce3afc9fa5811434713fc1b42194439dde9f8c6fdf"
    else
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "5aa8550878e3f159d5d8148119b3b68687d335652131902c57fe6d2c75bae585"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "63f16a0368eb40ed751b6d0a9e93b02b93ef124bdc3b81957dcf5bae27e61672"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "d5e2c4883ec3fb9e82328d52e7f5492e376306ac1c689b6abbdc59d424449795"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
