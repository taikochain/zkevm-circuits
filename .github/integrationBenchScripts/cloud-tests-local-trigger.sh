#!/bin/bash
set -eo pipefail

cd "$(dirname "$0")" || exit 1

GITHUB_RUN_ID=$1
REPOSITORY_URL=$2
BRANCH_NAME=$3
CIRCUIT=$4

PROVER_INSTANCE=$(cat "$HOME/CI_Github_Trigger/$GITHUB_RUN_ID/prover_instance")
echo "Prover instance at trigger: $PROVER_INSTANCE"

export PROVER_IP=$(tccli cvm DescribeInstances --InstanceIds "[\"$PROVER_INSTANCE\"]" | grep -A 1 PublicIpAddress | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
echo "Prover IP: $PROVER_IP"

rm ~/.ssh/known_hosts*

prepare_env() {
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" -- <../weeklyBenchScripts/00_installGo.sh
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" -- <../weeklyBenchScripts/00_installRust.sh
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" -- <../weeklyBenchScripts/01_installDeps.sh
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" -- <../weeklyBenchScripts/02_setup.sh
}

prepare_repo() {
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" -- "$GITHUB_RUN_ID" <../weeklyBenchScripts/03_prepareProver.sh
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" -- "$GITHUB_RUN_ID" "$REPOSITORY_URL" "$BRANCH_NAME" <../integrationBenchScripts/04_clone.sh
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" -- "$GITHUB_RUN_ID" <../weeklyBenchScripts/05_build.sh
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" -- <../weeklyBenchScripts/06_rsSysstat.sh &
  sleep 5

  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" -- "$DEGREE" "$CIRCUIT" "$GITHUB_RUN_ID" <../integrationBenchScripts/07_execBench.sh
  declare -g RESULT=$?
  chmod u+x ../integrationBenchScripts/08_processResults.sh
  ../integrationBenchScripts/08_processResults.sh "$CIRCUIT" "$DEGREE"
}

prepare_env
prepare_repo

kill_ssh() {
  sleep 30
  # Get the list of process IDs with the given IP address
  pids=$(ps aux | grep "$PROVER_IP" | grep -v "grep" | awk '{print $2}')

  # Loop through the process IDs and kill them
  for pid in $pids; do
    echo "Killing process with PID: $pid"
    kill "$pid"
  done
}

kill_ssh &

scp -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP":"$HOME"/CI_Prover_Benches/"$GITHUB_RUN_ID"/run_result ../../../
RESULT=$(cat ../../../run_result)
echo "exiting cloud-tests-local-trigger with RESULT $RESULT"
exit "$RESULT"
