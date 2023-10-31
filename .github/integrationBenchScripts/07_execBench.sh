#!/bin/bash
#set -eo pipefail

DEGREE=$1
GITHUB_RUN_ID=$2
PROVER=$3

export GOROOT="/usr/local/go"
export GOPATH="$HOME/go"
export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"

# Get the latest temp directory in the home directory
current_dir="$HOME"/CI_Prover_Benches/"$GITHUB_RUN_ID"

target_dir="$current_dir/zkevm-circuits"

printf -v _date '%(%Y-%m-%d_%H:%M:%S)T' -1

cd "$target_dir";

mkdir ../results
logfile="$_date"--"${PROVER}"_bench-"$DEGREE".proverlog


current_time=$(date +'%H:%M:%S')
echo "Current time: $current_time"
echo "$current_time" > ~/bench_begin
export RUST_BACKTRACE=1

export LIBCLANG_PATH="/usr/lib/x86_64-linux-gnu/"
export GETH_L2_URL="http://43.153.26.11:8545/"

if [ "$PROVER" == "Mock" ]; then
  echo "Running actions for Mock Prover"
  echo "~/.cargo/bin/cargo test --package integration-tests --test taiko_circuits -- mock_prover::serial_test_evm_circuit_block_anchor_only --exact --nocapture"
  ~/.cargo/bin/cargo test --package integration-tests --test taiko_circuits -- mock_prover::serial_test_evm_circuit_block_anchor_only --exact --nocapture > "$target_dir/../results/$logfile" 2>&1
elif [ "$PROVER" == "Real" ]; then
  echo "Running actions for Real Prover"
  echo "~/.cargo/bin/cargo test --package integration-tests --test taiko_circuits -- real_prover --nocapture"
  ~/.cargo/bin/cargo test --package integration-tests --test taiko_circuits -- real_prover --nocapture > "$target_dir/../results/$logfile" 2>&1
else
  echo "Unknown PROVER value: $PROVER"
  exit 1
fi

RESULT=$?
echo $RESULT > ../run_result
echo "exiting 07_exechBench.sh with RESULT $RESULT"

