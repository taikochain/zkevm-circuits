#!/bin/bash

echo "Triggering cleanup"
sshpass -p $BENCH_RESULTS_PASS ssh -t -t -o StrictHostKeyChecking=no ubuntu@43.130.90.57  "bash -s" -- "$GITHUB_RUN_ID" <bench-results-cleanup.sh

echo "Exiting github-action-cleanup"
exit 0
