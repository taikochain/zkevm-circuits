#!/bin/bash

previous_dir=$(ls -td -- "$HOME"/CI_Prover_Benches/* | head -2 | tac | head -1)
previous_path=$previous_dir/zkevm-circuits

# Get the latest temp directory in the home directory
latest_dir=$(ls -td -- "$HOME"/CI_Prover_Benches/* | head -1)

if [ -z "$latest_dir" ]; then
  echo "No temp directory found starting with 'backup_' in the home directory."
  exit 1
fi

if [ "$previous_dir" == "$latest_dir" ]; then
  echo "Could not find previous directory"

  # Clone the repository into the latest temp directory
  echo "Cloning the repository into the latest temp directory: $latest_dir"
  git clone https://github.com/taikoxyz/zkevm-circuits.git "$latest_dir/zkevm-circuits"

  # Print a message to indicate successful cloning
  echo "Repository cloned successfully into: $latest_dir/zkevm-circuits"

else
  echo "Found previous directory"

  cp -r $previous_path $latest_dir/
  rm -rf $latest_dir/zkevm-circuits/.github/weeklyBenchScripts/results
fi
