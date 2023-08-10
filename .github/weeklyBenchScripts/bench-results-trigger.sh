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

clone_zkevm-circuits() {
  git clone https://github.com/krzysztofpaliga/zkevm-circuits.git
  cd zkevm-circuits || exit 1
  git checkout krzysztofpaliga/benchmarks_weekly
  echo "Cloned zkevm-circuits"
}

ensure_git_installed
clone_zkevm-circuits

cd .github/weeklyBenchScripts || exit 1
chmod u+x bench-results-local-trigger.sh
./bench-results-local-trigger.sh $GITHUB_RUN_ID
echo "Exiting bench-results-trigger"
exit 0
