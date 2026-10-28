#!/usr/bin/env bash
# Fetch the corpus's one dependency (OpenZeppelin uniswap-hooks v1.2.1, pinned) into corpus/lib.
# Kept out of git submodules so `pip install git+...` stays a small clone.
set -euo pipefail
cd "$(dirname "$0")"
REV=acbd604c409a827f7f98c9517236da860c4fca1a
if [ ! -d lib/uniswap-hooks/.git ]; then
  git clone --quiet https://github.com/OpenZeppelin/uniswap-hooks lib/uniswap-hooks
fi
git -C lib/uniswap-hooks checkout --quiet "$REV"
git -C lib/uniswap-hooks submodule update --init --recursive --depth 1 --quiet
echo "corpus ready: run 'v4hooks bench' or 'pytest -m integration'"
