#!/bin/bash

echo "Triggering behchmark trigger"
sshpass -p $BENCH_RESULTS_PASS ssh -t -t -o StrictHostKeyChecking=no ubuntu@43.130.90.57 "bash -s" -- "$GITHUB_RUN_ID" <bench-results-trigger.sh

echo "Exiting github-action-trigger"
exit 0
