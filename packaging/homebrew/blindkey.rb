# Homebrew formula for Blindkey (source build).
#
# Canonical copy lives in the repo; publish it to a tap so users can:
#   brew install leocelis/tap/blindkey
# To set up the tap (one-time, maintainer):
#   1. Create the repo leocelis/homebrew-tap
#   2. Copy this file to Formula/blindkey.rb there
#   3. After cutting v1.0.0, fill in `url`/`sha256` for the stable stanza:
#        url "https://github.com/leocelis/blindkey/archive/refs/tags/v1.0.0.tar.gz"
#        sha256 "<shasum -a 256 of that tarball>"
#
# Until then, `brew install --HEAD leocelis/tap/blindkey` builds from main.
class Blindkey < Formula
  desc "Local-first credential vault your AI agents can use but never see"
  homepage "https://github.com/leocelis/blindkey"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/leocelis/blindkey.git", branch: "main"

  # Stable stanza — uncomment and fill in after the first tagged release:
  # url "https://github.com/leocelis/blindkey/archive/refs/tags/v1.0.0.tar.gz"
  # sha256 "REPLACE_WITH_TARBALL_SHA256"

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", "--path", "crates/blindkey-cli", "--root", prefix
  end

  test do
    # `blindkey` reads all secrets interactively / from files, never argv, so a version probe
    # is the safe smoke test.
    assert_match "blindkey", shell_output("#{bin}/blindkey --version")
  end
end
