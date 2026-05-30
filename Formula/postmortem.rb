class Postmortem < Formula
  desc "Static dependency scanner for Node, Python and Rust projects"
  homepage "https://github.com/Sn0wAlice/postmortem"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Sn0wAlice/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "66463b8132fccae514277498f02885b9be93d9b644650ad0a7c2c7a316dc6907"
    else
      url "https://github.com/Sn0wAlice/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "f4f174933f29727a787f2992feaa0da2ee13f3998fdcc16169216e0cc96d37fc"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/Sn0wAlice/postmortem/releases/download/v#{version}/postmortem-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "1ea75d0ec124572f4087b58f35f3d077744e3a81c81f7e623b35595b83c8de3d"
    elsif Hardware::CPU.arm?
      url "https://github.com/Sn0wAlice/postmortem/releases/download/v#{version}/postmortem-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "411b034d30d9cfc00dd4c29cd3bb0e259e199a80d9b2d6cc2db779303c9825e5"
    end
  end

  def install
    bin.install "postmortem"
  end

  test do
    assert_match "postmortem", shell_output("#{bin}/postmortem --version")
  end
end
