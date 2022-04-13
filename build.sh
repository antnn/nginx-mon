#!/bin/bash
#export user=root
set -Eeuo pipefail
set -o nounset
set -o errexit
declare DEBUG


cargo xtask build-ebpf --release 
cargo build --release --target=x86_64-unknown-linux-musl
cargo xtask run --release  --target=x86_64-unknown-linux-musl