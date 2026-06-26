set -euo pipefail

# 1. build deps (these drive the seccomp/btrfs/openpgp build tags)
sudo apt-get update
sudo apt-get install -y make git gcc pkg-config jq \
  libseccomp-dev libgpgme-dev libbtrfs-dev

# 2. Go 1.25 (go.mod requires it)
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q 'go1.25'; then
  curl -fsSL https://go.dev/dl/go1.25.0.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
fi
export PATH=$PATH:/usr/local/go/bin

# 3. clone YOUR repo + check out the branch (full clone, so the SHA is reachable)
rm -rf leehun-cri-o
git clone https://github.com/vitu-mafeni/leehun-cri-o.git
cd leehun-cri-o
git checkout 2026-02-03/support-restore-from-file

# 4. build just the binary; vcs.revision is stamped from this checkout
make binaries

# 5. derive the commit FROM the binary, so the asset can never drift
#    from what crio actually reports at runtime
./bin/crio version --json | jq -r .gitCommit > bin/crio.commit
echo "built commit: $(cat bin/crio.commit)"

# 6. publish to a release on YOUR repo
gh auth status || gh auth login
gh release create crio-1.35.0-restore-from-file \
  bin/crio bin/crio.commit \
  --repo vitu-mafeni/leehun-cri-o \
  --title "crio 1.35.0 (support-restore-from-file)" \
  --notes "Custom CRI-O 1.35.0 with restore-from-file."
