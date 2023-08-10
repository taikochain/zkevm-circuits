#!/bin/bash

echo "Triggering cleanup"
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- "$DEGREE" "$CIRCUIT" "$GITHUB_RUN_ID" <07_execBench.sh

sshpass -p $BENCH_RESULTS_PASS ssh -t -t -o StrictHostKeyChecking=no ubuntu@43.130.90.57  "bash -s" -- "$GITHUB_RUN_ID" <bench-results-local-cleanup.sh

echo "Exiting github-action-cleanup"
exit 0
