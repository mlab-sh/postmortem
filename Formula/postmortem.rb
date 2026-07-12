class Postmortem < Formula
  desc "Static dependency scanner for Node, Python and Rust projects"
  homepage "https://github.com/mlab-sh/postmortem"
  version "1.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "d899c8f7734365d1012844b04f85310afb0b0b9b9a2e68c880716a0c6bbec955"
    else
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "11dadcb54a7e58ba676c66daac974415a37b5585abb25ceaae3a896cc7217ac5"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "245a2069ecc8493b9a13479f258d45820f6cb8b20a05b810e850ce6addf3c912"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5153d8122e7f3bdfd4c5436a633e1be35c9dbd9626dca1fec860fabc2091fef9"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
