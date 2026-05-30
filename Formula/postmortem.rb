class Postmortem < Formula
  desc "Static dependency scanner for Node, Python and Rust projects"
  homepage "https://github.com/mlab-sh/postmortem"
  version "1.0.1"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "a029491a12b54a0a2c35377d18d96c4bc3f84e1841846288e1caf4dd07781cee"
    else
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "47f12809ce5ad982d35b97993bc483fec0226ab53844468bbc10ba79e6bbfa64"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "bae76694e215da181a54e38c1ac73db6b4f45a6646c8d03a64731a9590238649"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "8092f947da15a11fd4ef79ec85b10480acd35c58c3bc8eff3ba7948f072af80b"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
