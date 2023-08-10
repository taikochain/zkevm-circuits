#!/bin/bash

GITHUB_RUN_ID=$1

# Get the latest temp directory in the home directory
current_dir="$HOME"/CI_Prover_Benches/"$GITHUB_RUN_ID"

# Clone the repository into the latest temp directory
echo "Cloning the repository into the latest temp directory: $current_dir"
git clone https://github.com/taikoxyz/zkevm-circuits.git "$current_dir/zkevm-circuits"

# Print a message to indicate successful cloning
echo "Repository cloned successfully into: $current_dir/zkevm-circuits"
