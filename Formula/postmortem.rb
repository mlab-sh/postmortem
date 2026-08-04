class Postmortem < Formula
  desc "Static dependency scanner for Node, Python and Rust projects"
  homepage "https://github.com/mlab-sh/postmortem"
  version "2.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "7d033299ffb6cffbab79831631754f7523e4558a1d6d31c8839ec836bfed5a1e"
    else
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "724aafd8f128494e99962c1c40358bf24ffd86284a32b6096ce1336a3023e2ad"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "bd35233a75ac732f4a8fdfc4a20a8681dce748e3184326bc01287232c1177abd"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "441de99d6f7fc3eecb6fa79779071f4dfbaf1244504dd0faa5538ac4d0b8ea54"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
