#!/bin/bash

ensure_git_installed() {
  if ! command -v git &>/dev/null; then
    echo "Git is not installed. Installing..."
    sudo apt update
    sudo apt install -y git
  else
    echo "Git is already installed."
  fi
}

make_temp_dir() {
  # Get the current timestamp
  timestamp=$(date +%Y-%m-%d_%H-%M-%S)

  # Set up the directory name with the timestamp
  directory_name="CI_Github_Trigger/$timestamp"

  # Set up the full path for the directory in the home directory
  directory_path="$HOME/$directory_name"

  # Create the directory
  mkdir -p "$directory_path"

  cd "$directory_path" || exit 1

  echo "Directory '$directory_name' with timestamp '$timestamp' has been created in the home directory."
}

clone_zkevm-circuits() {
  git clone https://github.com/taikoxyz/zkevm-circuits.git

  cd zkevm-circuits || exit 1
  git checkout krzysztofpaliga/weekly_bench
  echo "Cloned zkevm-circuits"
}

ensure_git_installed
make_temp_dir
clone_zkevm-circuits

cd .github/weeklyBenchScripts || exit 1
chmod u+x bench-results-local-trigger.sh
./bench-results-local-trigger.sh
