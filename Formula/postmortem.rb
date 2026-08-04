class Postmortem < Formula
  desc "Static dependency scanner for Node, Python and Rust projects"
  homepage "https://github.com/mlab-sh/postmortem"
  version "2.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "aed3f3b070613a025ae66f31aad6450ca41c44febbf9b53153d175b27087878f"
    else
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "f7f71bc4db0d0610aa115ef2825940e3ecfa1771623d4705011347d3bf88d18a"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "46835ddf69110b76b16acb5ec6eb5916647c3e819229aa4c338c7e34af304374"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "4a5d198b4dd46d84303232ff24a5d6f5647eb754cc2f5bc79c4e037e785b378a"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
