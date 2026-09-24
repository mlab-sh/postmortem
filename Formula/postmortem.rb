class Postmortem < Formula
  desc "Supply-chain scanner. Flags malicious install code, typosquats, and shady provenance across your dependencies and your OS packages. Repo-reputation scoring, known-CVE intel, no telemetry."
  homepage "https://github.com/mlab-sh/postmortem"
  version "2.7.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "3b4c97d5d60b0991cdd5023b942cbeb7758817f4405982599549fd24ec16cd84"
    else
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "973032ef4cfdccfd65511d7e92a2da9e4ccfc919f61f8d668446e5569d5817cd"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "b9c52cddaab59e2beb205397cb7eac4776608f9220ae5774faa289188d95a856"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "ea391df9a390c3306a0c9bb2d2aa23894c5cdb79832893618daeecc1f251fca6"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
