#!/bin/bash
GITHUB_RUN_ID=$1
echo "Performing cleanup... $GITHUB_RUN_ID"
sleep 60
PROVER_INSTANCE=$(cat ~/prover_instance_weekly_"$GITHUB_RUN_ID")
echo "Prover instance at cleanup: $PROVER_INSTANCE"
tccli cvm TerminateInstances --InstanceIds "[\"$PROVER_INSTANCE\"]" --ReleasePrepaidDataDisk True
echo "Exiting bench-results-local-cleanup"
rm ~/prover_instance_weekly_"$GITHUB_RUN_ID"
pkill ssh
exit 0
