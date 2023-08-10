#!/bin/bash

ensure_ssh_and_sshpass_installed() {
  # Check if 'ssh' is installed
  if ! command -v ssh &>/dev/null; then
    echo "ssh is not installed. Installing..."
    sudo apt update
    sudo apt install -y openssh-client
  else
    echo "ssh is already installed."
  fi

  # Check if 'sshpass' is installed
  if ! command -v sshpass &>/dev/null; then
    echo "sshpass is not installed. Installing..."
    sudo apt update
    sudo apt install -y sshpass
  else
    echo "sshpass is already installed."
  fi
}

ensure_ssh_and_sshpass_installed

sshpass -p $BENCH_RESULTS_PASS ssh -t -t -o StrictHostKeyChecking=no ubuntu@43.130.90.57 <<EOF
echo "Started executing bench-results-trigger" >&2
$(<bench-results-trigger.sh "$GITHUB_RUN_ID")
echo "Finished executing bench-results-trigger" >&2
exit 0
EOF

echo "Exiting github-action-trigger"
exit 0
