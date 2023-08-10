#!/bin/bash

echo "Triggering cleanup"
sshpass -p $BENCH_RESULTS_PASS ssh -t -t -o StrictHostKeyChecking=no ubuntu@43.130.90.57 <<EOF
echo "Started executing bench-results-local-cleanup" >&2
$(<bench-results-local-cleanup.sh)
echo "Finished executing bench-results-local-cleanup" >&2
exit 0
EOF

echo "Exiting github-action-cleanup"
exit 0
