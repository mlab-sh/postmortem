class Postmortem < Formula
  desc "Static dependency scanner for Node, Python and Rust projects"
  homepage "https://github.com/mlab-sh/postmortem"
  version "2.1.2"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "f418932fc313d5168f8b48700f28a55e42f2c30c3cc35f8bfc71d1a259a15fc4"
    else
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "7b6c7569d17e49d8785ad156b742c3ce998dd79ae3d7610f2167abefe967bb7a"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "366d5800fcf07b14a67f7d813e04134acb599527f254d2584436680c23d88af7"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "885e281304036ab64f4b23c2bfd5dc1cf710031fb22400ee7b2e71a00122f1b9"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
