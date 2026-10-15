# Homebrew formula template for bd. scripts/render-packaging.sh fills the
# placeholders (between @ signs) from a release's SHA256SUMS; copy the rendered file into a tap.
class Bd < Formula
  desc "Coordination engine for agents and people, on SQLite"
  homepage "https://github.com/@REPO@"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/@REPO@/releases/download/@TAG@/bd-@TAG@-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256_AARCH64_APPLE_DARWIN@"
    end
    on_intel do
      url "https://github.com/@REPO@/releases/download/@TAG@/bd-@TAG@-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256_X86_64_APPLE_DARWIN@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/@REPO@/releases/download/@TAG@/bd-@TAG@-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_AARCH64_UNKNOWN_LINUX_MUSL@"
    end
    on_intel do
      url "https://github.com/@REPO@/releases/download/@TAG@/bd-@TAG@-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_X86_64_UNKNOWN_LINUX_MUSL@"
    end
  end

  def install
    bin.install "bd"
    bash_completion.install "completions/bd.bash" => "bd" if File.exist?("completions/bd.bash")
    zsh_completion.install "completions/_bd" if File.exist?("completions/_bd")
    fish_completion.install "completions/bd.fish" if File.exist?("completions/bd.fish")
  end

  test do
    assert_match "bd #{version}", shell_output("#{bin}/bd --version")
  end
end
