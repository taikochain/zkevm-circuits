#!/bin/bash
GITHUB_RUN_ID=$1

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
  # Set up the directory name with the timestamp
  directory_name="CI_Github_Trigger/$GITHUB_RUN_ID"

  # Set up the full path for the directory in the home directory
  directory_path="$HOME/$directory_name"

  # Create the directory
  mkdir -p "$directory_path"

  cd "$directory_path" || exit 1

  echo "Directory '$directory_name' with GITHUB_RUN_ID '$GITHUB_RUN_ID' has been created in the home directory."
}

clone_zkevm-circuits() {
  git clone https://github.com/krzysztofpaliga/zkevm-circuits.git
  cd zkevm-circuits || exit 1
  git checkout krzysztofpaliga/benchmarks_weekly
  echo "Cloned zkevm-circuits"
}

ensure_git_installed
make_temp_dir
clone_zkevm-circuits

cd .github/weeklyBenchScripts || exit 1
chmod u+x bench-results-local-trigger.sh
./bench-results-local-trigger.sh $GITHUB_RUN_ID
echo "Exiting bench-results-trigger"
exit 0
