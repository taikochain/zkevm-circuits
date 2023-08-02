#!/bin/bash
export GOROOT="/usr/local/go"
export GOPATH="$HOME/go"
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"

# Get the latest temp directory in the home directory
latest_dir=$(ls -td -- "$HOME"/CI_Prover_Benches/* | head -1)

if [ -z "$latest_dir" ]; then
    echo "No temp directory found starting with 'CI_Prover_Benches__' in the home directory."
    exit 1
fi

# Clone the repository into the latest temp directory
echo "Building zkevm-circuits inside: $latest_dir"
cd "$latest_dir/zkevm-circuits"
~/.cargo/bin/cargo build

