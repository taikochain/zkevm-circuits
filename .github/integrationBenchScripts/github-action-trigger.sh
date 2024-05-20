#!/bin/bash
set -eo pipefail

echo "Triggering cloud-tests-trigger.sh with $GITHUB_RUN_ID $REPOSITORY_URL $BRANCH_NAME $PROVER"
sshpass -p "$BENCH_RESULTS_PASS" ssh -o StrictHostKeyChecking=no ubuntu@43.130.90.57 "bash -s" -- "$GITHUB_RUN_ID" "$REPOSITORY_URL" "$BRANCH_NAME" "$PROVER" <cloud-tests-trigger.sh
RESULT=$?
echo "exiting github-action-trigger with RESULT=$RESULT"
exit $RESULT