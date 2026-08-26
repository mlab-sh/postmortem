class Postmortem < Formula
  desc "Supply-chain scanner. Flags malicious install code, typosquats, and shady provenance across your dependencies and your OS packages. Repo-reputation scoring, known-CVE intel, no telemetry."
  homepage "https://github.com/mlab-sh/postmortem"
  version "2.3.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "a42b7502e6d97c17dd819fca33cba4e4d5624215f0d702775413db0542d3760a"
    else
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "fc288a0c7889944ae0374976997b32390e374e2c4001cdadcf5c5085143a3607"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "f50677678a5d2de1d19a387c1a997116c330605b8a07bfbd0a8cd8bd89546846"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "7ddc130c21bdcb517633bb239d593b4c7e95a1bf5916323dce9aed76d8858af0"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
