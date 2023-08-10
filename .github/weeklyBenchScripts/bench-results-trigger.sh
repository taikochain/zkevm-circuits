#!/bin/bash

cleanup() {
  echo "Performing cleanup..."
  PROVER_INSTANCE=$(cat prover_instance)
  echo "Prover instance: $PROVER_INSTANCE"
  tccli cvm TerminateInstances --InstanceIds "[\"$PROVER_INSTANCE\"]" --ReleasePrepaidDataDisk True
  echo "Exiting bench-results-local-trigger"
  pkill ssh
  exit 0
}

# Set up the trap to execute the cleanup function on SIGINT (Ctrl+C) and SIGTERM (kill)
trap cleanup HUP INT TERM QUIT EXIT

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
  git clone https://github.com/krzysztofpaliga/zkevm-circuits.git


  cd zkevm-circuits || exit 1
  echo "Cloned zkevm-circuits"
}

ensure_git_installed
make_temp_dir
clone_zkevm-circuits

cd .github/weeklyBenchScripts || exit 1
chmod u+x bench-results-local-trigger.sh
./bench-results-local-trigger.sh
echo "Exiting bench-results-trigger"
exit 0
