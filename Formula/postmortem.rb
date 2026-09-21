class Postmortem < Formula
  desc "Supply-chain scanner. Flags malicious install code, typosquats, and shady provenance across your dependencies and your OS packages. Repo-reputation scoring, known-CVE intel, no telemetry."
  homepage "https://github.com/mlab-sh/postmortem"
  version "2.5.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "4a1a5b7d43561d05937fda9a4ccd912ace9692e1baeca29cd53ec1cfe34ddb14"
    else
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "425603b395ae63d22c637e52a7b007413ff5880131192e4b5702676b411935c6"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c60f578273cb747bcb54cb8f022fc221bf28689e4550178e290ce74d49ff47e5"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "206debc0e231a9fcaac12e980b75389e20fb59a292e0841403131a998941dca5"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
