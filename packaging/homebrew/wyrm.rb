# Homebrew formula for wyrm. Put this in a tap repo (`1ARdotNO/homebrew-wyrm`)
# so users can `brew install 1ARdotNO/wyrm/wyrm`. Bump `version` + the four
# sha256s on each release (or automate with `brew bump-formula-pr`).
class Wyrm < Formula
  desc "Threat modeling that lives with your code — OTM validation and STRIDE analysis"
  homepage "https://github.com/1ARdotNO/wyrm"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/1ARdotNO/wyrm/releases/download/v0.1.0/wyrm-aarch64-apple-darwin.tar.gz"
      sha256 "1f5973a74d5701bff8c24eaa04185f8b68425006c7d764d84577e26ccd8ba7b3"
    end
    on_intel do
      url "https://github.com/1ARdotNO/wyrm/releases/download/v0.1.0/wyrm-x86_64-apple-darwin.tar.gz"
      sha256 "32ce3eea02128f5c555cea28cf9275ee3b456e03cde5262ce83cc8cfb0ea5418"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/1ARdotNO/wyrm/releases/download/v0.1.0/wyrm-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0d85f19379256faebe918e963817f0a3174fa04a50adfc92fa891204713512a8"
    end
    on_intel do
      url "https://github.com/1ARdotNO/wyrm/releases/download/v0.1.0/wyrm-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "34835267c193d9ce6864431be8b40867a8022ea5c33a4f4a8782f2658151caab"
    end
  end

  def install
    bin.install "wyrm"
  end

  test do
    assert_match "wyrm", shell_output("#{bin}/wyrm --version")
  end
end
