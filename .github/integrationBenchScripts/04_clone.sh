#!/bin/bash
set -eo pipefail

GITHUB_RUN_ID=$1
REPOSITORY_URL=$2
BRANCH_NAME=$3

# Get the latest temp directory in the home directory
current_dir="$HOME"/CI_Prover_Benches/"$GITHUB_RUN_ID"
target_dir="$current_dir"/zkevm-circuits

if [ ! -d "$target_dir" ]; then
  # Clone the repository into the latest temp directory
  echo "Cloning the repository $REPOSITORY_URL into the latest temp directory: $current_dir"
  git clone -q "$REPOSITORY_URL" "$current_dir/zkevm-circuits"

  if [ -n "$BRANCH_NAME" ]; then
    old_dir=$(pwd)
    cd "$current_dir/zkevm-circuits" || exit 1
    git checkout "$BRANCH_NAME"
    cd "$old_dir" || exit 1
  fi
  # Print a message to indicate successful cloning
  echo "Repository $REPOSITORY_URL cloned successfully into: $current_dir/zkevm-circuits"
fi
