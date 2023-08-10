#!/bin/bash
GITHUB_RUN_ID=$1
export GOROOT="/usr/local/go"
export GOPATH="$HOME/go"
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH:$HOME/.cargo/bin/"

# Get the latest temp directory in the home directory
current_dir="$HOME"/CI_Prover_Benches/"$GITHUB_RUN_ID"

target_dir="$current_dir/zkevm-circuits"

cd $target_dir || exit 1

# ENTER YOUR TEST COMMAND BELOW
make test-all