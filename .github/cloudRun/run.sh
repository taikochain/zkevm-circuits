#!/bin/bash
#set -eo pipefail

GITHUB_RUN_ID=$1
export GOROOT="/usr/local/go"
export GOPATH="$HOME/go"
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH:$HOME/.cargo/bin/"

# Get the latest temp directory in the home directory
current_dir="$HOME"/CI_Prover_Benches/"$GITHUB_RUN_ID"

target_dir="$current_dir/zkevm-circuits"

cd "$target_dir" || exit 1

# ENTER YOUR TEST COMMAND BELOW
cd zkevm-circuits/fuzz
cargo install cargo-fuzz
cargo fuzz run -v -j 64 evm -- -rss_limit_mb=9999999999 -max_len=99999999
# ENTER YOUR TEST COMMAND ABOVE

RESULT=$?
echo $RESULT > ../run_result
echo "exiting run.sh with RESULT $RESULT"

sleep 72h